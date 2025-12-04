package com.gateway.auth.service;

import com.gateway.auth.exception.AccountLockedException;
import com.gateway.auth.exception.InvalidTokenException;
import com.gateway.auth.exception.WeakPasswordException;
import com.gateway.auth.model.*;
import com.gateway.auth.repository.*;
import com.gateway.auth.security.JwtUtil;
import com.gateway.auth.util.PasswordValidator;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserRepository userRepository;
    private final OTPRepository otpRepository;
    private final OTPService otpService;
    private final EmailService emailService;
    private final BCryptPasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final RefreshTokenService refreshTokenService;
    private final AuditLogService auditLogService;
    private final PasswordValidator passwordValidator;

    @Value("${auth.max-failed-attempts:5}")
    private int maxFailedAttempts;

    @Value("${auth.lockout-duration-minutes:30}")
    private int lockoutDurationMinutes;

    @Value("${auth.email.verification.required:true}")
    private boolean emailVerificationRequired;

    @Transactional
    public void register(String email, String rawPassword, String name, HttpServletRequest request) {
        // Validate password strength
        PasswordValidator.ValidationResult validationResult = passwordValidator.validate(rawPassword, email);
        if (!validationResult.isValid()) {
            auditLogService.logAuthFailure(email, AuditAction.REGISTER, validationResult.getErrorMessage(), request);
            throw new WeakPasswordException(validationResult.getErrorMessage());
        }

        // Check if email already exists
        if (userRepository.findByEmail(email).isPresent()) {
            auditLogService.logAuthFailure(email, AuditAction.REGISTER, "Email already registered", request);
            throw new RuntimeException("Email already registered");
        }

        // Create user
        User user = User.builder()
                .email(email)
                .password(passwordEncoder.encode(rawPassword))
                .name(name)
                .role(Role.USER)
                .isEmailVerified(false)
                .failedLoginAttempts(0)
                .build();

        userRepository.save(user);
        log.info("User registered: {}", email);

        // Generate OTP and send email (only if verification required)
        if (emailVerificationRequired) {
            OTP otp = otpService.generateOTP(user, OTPPurpose.EMAIL_VERIFICATION, 15);
            String emailBody = buildVerificationEmail(user.getName(), otp.getOtpCode());
            
            // Log OTP for development convenience
            log.info("Generated OTP for {}: {}", user.getEmail(), otp.getOtpCode());
            
            try {
                emailService.sendSimpleMessage(user.getEmail(), "Verify your email - Gateway", emailBody);
                auditLogService.logAuthEvent(user.getId(), email, AuditAction.EMAIL_VERIFICATION_SENT, true, request);
            } catch (Exception e) {
                log.warn("Failed to send verification email to {}: {}", email, e.getMessage());
                // In dev mode, auto-verify if email fails
                if (!emailVerificationRequired) {
                    user.setEmailVerified(true);
                    userRepository.save(user);
                }
            }
        } else {
            // Auto-verify in development mode
            user.setEmailVerified(true);
            userRepository.save(user);
            log.info("Email verification skipped (dev mode) for: {}", email);
        }

        // Audit log
        auditLogService.logAuthEvent(user.getId(), email, AuditAction.REGISTER, true, request);
    }

    @Transactional
    public LoginResult login(String email, String rawPassword, HttpServletRequest request) {
        Optional<User> userOpt = userRepository.findByEmail(email);
        
        if (userOpt.isEmpty()) {
            auditLogService.logAuthFailure(email, AuditAction.LOGIN_FAILED, "User not found", request);
            throw new RuntimeException("Invalid credentials");
        }

        User user = userOpt.get();

        // Check if account is locked
        if (user.isAccountLocked()) {
            long minutesRemaining = Duration.between(LocalDateTime.now(), user.getAccountLockedUntil()).toMinutes();
            auditLogService.logAuthFailure(email, AuditAction.LOGIN_FAILED, 
                "Account locked for " + minutesRemaining + " more minutes", request);
            throw new AccountLockedException(
                "Account is locked due to too many failed login attempts. Try again in " + minutesRemaining + " minutes.",
                minutesRemaining
            );
        }

        // Validate password
        if (!passwordEncoder.matches(rawPassword, user.getPassword())) {
            handleFailedLogin(user, request);
            throw new RuntimeException("Invalid credentials");
        }

        // Check email verification (skip if not required in dev mode)
        if (emailVerificationRequired && !user.isEmailVerified()) {
            auditLogService.logAuthFailure(email, AuditAction.LOGIN_FAILED, "Email not verified", request);
            return new LoginResult(null, null, false, "Email not verified. Please check your email for the verification code.");
        }

        // Successful login
        user.resetFailedAttempts();
        user.setLastLoginAt(LocalDateTime.now());
        userRepository.save(user);

        // Generate tokens
        String accessToken = jwtUtil.generateToken(user.getEmail());
        String ipAddress = auditLogService.extractIpAddress(request);
        String userAgent = request.getHeader("User-Agent");
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user, ipAddress, userAgent);

        log.info("User logged in successfully: {}", email);
        auditLogService.logAuthEvent(user.getId(), email, AuditAction.LOGIN_SUCCESS, true, request);

        return new LoginResult(accessToken, refreshToken.getToken(), true, null);
    }

    @Transactional
    protected void handleFailedLogin(User user, HttpServletRequest request) {
        user.incrementFailedAttempts();
        
        if (user.getFailedLoginAttempts() >= maxFailedAttempts) {
            user.lockAccount(lockoutDurationMinutes);
            userRepository.save(user);
            log.warn("Account locked due to {} failed attempts: {}", maxFailedAttempts, user.getEmail());
            auditLogService.logAuthEvent(user.getId(), user.getEmail(), AuditAction.ACCOUNT_LOCKED, true, request);
            throw new AccountLockedException(
                "Account locked due to too many failed login attempts. Try again in " + lockoutDurationMinutes + " minutes.",
                lockoutDurationMinutes
            );
        }

        userRepository.save(user);
        auditLogService.logAuthFailure(user.getEmail(), AuditAction.LOGIN_FAILED, 
            "Invalid password (attempt " + user.getFailedLoginAttempts() + "/" + maxFailedAttempts + ")", request);
    }

    @Transactional
    public TokenRefreshResult refreshAccessToken(String refreshTokenString, HttpServletRequest request) {
        RefreshToken refreshToken = refreshTokenService.findByToken(refreshTokenString)
                .orElseThrow(() -> new InvalidTokenException("Invalid refresh token"));

        if (!refreshTokenService.validateRefreshToken(refreshToken)) {
            auditLogService.logAuthFailure(refreshToken.getUser().getEmail(), AuditAction.TOKEN_REFRESHED, 
                "Invalid or expired refresh token", request);
            throw new InvalidTokenException("Refresh token is invalid or expired");
        }

        User user = refreshToken.getUser();
        String newAccessToken = jwtUtil.generateToken(user.getEmail());

        log.debug("Access token refreshed for user: {}", user.getEmail());
        auditLogService.logAuthEvent(user.getId(), user.getEmail(), AuditAction.TOKEN_REFRESHED, true, request);

        return new TokenRefreshResult(newAccessToken, refreshTokenString);
    }

    @Transactional
    public void logout(String refreshTokenString, HttpServletRequest request) {
        refreshTokenService.findByToken(refreshTokenString).ifPresent(token -> {
            User user = token.getUser();
            refreshTokenService.revokeToken(refreshTokenString);
            auditLogService.logAuthEvent(user.getId(), user.getEmail(), AuditAction.LOGOUT, true, request);
            log.info("User logged out: {}", user.getEmail());
        });
    }

    @Transactional
    public boolean verifyEmailOTP(String otpCode, HttpServletRequest request) {
        String trimmedOtp = otpCode != null ? otpCode.trim() : null;
        log.info("Attempting to verify OTP: '{}'", trimmedOtp);
        var otpOpt = otpRepository.findByOtpCodeAndPurposeAndIsUsedFalse(trimmedOtp, OTPPurpose.EMAIL_VERIFICATION);
        
        if (otpOpt.isEmpty()) {
            log.warn("OTP verification failed: Code '{}' not found or already used", otpCode);
            auditLogService.logAuthFailure(null, AuditAction.EMAIL_VERIFICATION_FAILED, "Invalid OTP", request);
            return false;
        }

        OTP otp = otpOpt.get();
        LocalDateTime now = LocalDateTime.now();
        log.info("OTP found. Expires at: {}, Current time: {}", otp.getExpiresAt(), now);
        
        if (otp.getExpiresAt().isBefore(now)) {
            log.warn("OTP verification failed: Expired. Expires at: {}, Now: {}", otp.getExpiresAt(), now);
            auditLogService.logAuthFailure(otp.getUser().getEmail(), AuditAction.EMAIL_VERIFICATION_FAILED, 
                "OTP expired", request);
            return false;
        }

        // Mark OTP as used and verify user
        otpService.markUsed(otp);
        User user = otp.getUser();
        user.setEmailVerified(true);
        userRepository.save(user);

        log.info("Email verified for user: {}", user.getEmail());
        auditLogService.logAuthEvent(user.getId(), user.getEmail(), AuditAction.EMAIL_VERIFIED, true, request);
        
        return true;
    }

    @Transactional
    public void resendVerificationOtp(String email, HttpServletRequest request) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (user.isEmailVerified()) {
            throw new RuntimeException("Email already verified");
        }

        OTP otp = otpService.generateOTP(user, OTPPurpose.EMAIL_VERIFICATION, 15);
        String emailBody = buildVerificationEmail(user.getName(), otp.getOtpCode());
        emailService.sendSimpleMessage(user.getEmail(), "Verify your email - Resend", emailBody);

        log.info("Verification OTP resent to: {}", email);
        auditLogService.logAuthEvent(user.getId(), email, AuditAction.OTP_RESENT, true, request);
    }

    @Transactional
    public void requestPasswordReset(String email, HttpServletRequest request) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Generate OTP for password reset (15 minutes validity)
        OTP otp = otpService.generateOTP(user, OTPPurpose.PASSWORD_RESET, 15);
        
        // Send email with OTP
        String emailBody = buildPasswordResetEmail(user.getName(), otp.getOtpCode());
        emailService.sendSimpleMessage(user.getEmail(), "Password Reset - Gateway", emailBody);

        log.info("Password reset OTP sent to: {}", email);
        auditLogService.logAuthEvent(user.getId(), email, AuditAction.PASSWORD_RESET_REQUESTED, true, request);
    }

    @Transactional
    public void resetPassword(String otpCode, String newPassword, HttpServletRequest request) {
        // Find valid OTP
        var otpOpt = otpRepository.findByOtpCodeAndPurposeAndIsUsedFalse(otpCode, OTPPurpose.PASSWORD_RESET);
        
        if (otpOpt.isEmpty()) {
            throw new RuntimeException("Invalid or already used OTP");
        }

        OTP otp = otpOpt.get();
        
        // Check expiry
        if (otp.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new RuntimeException("OTP has expired");
        }

        User user = otp.getUser();

        // Validate new password
        PasswordValidator.ValidationResult validationResult = passwordValidator.validate(newPassword, user.getEmail());
        if (!validationResult.isValid()) {
            auditLogService.logAuthFailure(user.getEmail(), AuditAction.PASSWORD_RESET_FAILED, 
                validationResult.getErrorMessage(), request);
            throw new WeakPasswordException(validationResult.getErrorMessage());
        }

        // Update password
        user.setPassword(passwordEncoder.encode(newPassword));
        user.resetFailedAttempts(); // Reset any lockout
        userRepository.save(user);
        
        // Mark OTP as used
        otpService.markUsed(otp);

        // Revoke all refresh tokens for security
        refreshTokenService.revokeAllUserTokens(user);

        log.info("Password reset successful for: {}", user.getEmail());
        auditLogService.logAuthEvent(user.getId(), user.getEmail(), AuditAction.PASSWORD_RESET_SUCCESS, true, request);
    }

    private String buildVerificationEmail(String name, String otpCode) {
        return String.format("""
            Hello %s,
            
            Thank you for registering with Gateway!
            
            Your email verification code is: %s
            
            This code will expire in 15 minutes.
            
            If you didn't request this, please ignore this email.
            
            Best regards,
            Gateway Team
            """, name, otpCode);
    }

    private String buildPasswordResetEmail(String name, String otpCode) {
        return String.format("""
            Hello %s,
            
            We received a request to reset your password.
            
            Your password reset code is: %s
            
            This code will expire in 15 minutes.
            
            If you didn't request this, please ignore this email and your password will remain unchanged.
            
            Best regards,
            Gateway Team
            """, name, otpCode);
    }

    // DTOs
    public record LoginResult(String accessToken, String refreshToken, boolean emailVerified, String message) {}
    public record TokenRefreshResult(String accessToken, String refreshToken) {}
}

