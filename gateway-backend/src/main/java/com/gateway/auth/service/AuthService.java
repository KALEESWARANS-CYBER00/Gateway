package com.gateway.auth.service;

import com.gateway.auth.model.*;
import com.gateway.auth.repository.*;
import com.gateway.auth.security.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final OTPRepository otpRepository;
    private final OTPService otpService;
    private final EmailService emailService;
    private final BCryptPasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    public void register(String email, String rawPassword, String name) {
        if (userRepository.findByEmail(email).isPresent()) {
            throw new RuntimeException("Email already registered");
        }

        User user = User.builder()
                .email(email)
                .password(passwordEncoder.encode(rawPassword))
                .name(name)
                .role(Role.USER)
                .isEmailVerified(false)
                .build();

        userRepository.save(user);

        // generate OTP and send email
        OTP otp = otpService.generateOTP(user, OTPPurpose.EMAIL_VERIFICATION, 15);
        String body = "Your email verification code is: " + otp.getOtpCode();
        emailService.sendSimpleMessage(user.getEmail(), "Verify your email", body);
    }

    public LoginResult login(String email, String rawPassword) {
        Optional<User> userOpt = userRepository.findByEmail(email);
        if (userOpt.isEmpty()) throw new RuntimeException("Invalid credentials");

        User user = userOpt.get();
        if (!passwordEncoder.matches(rawPassword, user.getPassword())) {
            throw new RuntimeException("Invalid credentials");
        }

        String token = jwtUtil.generateToken(user.getEmail());
        return new LoginResult(token, user.isEmailVerified());
    }

    public boolean verifyEmailOTP(String otpCode) {
        var otpOpt = otpRepository.findByOtpCodeAndPurposeAndIsUsedFalse(otpCode, OTPPurpose.EMAIL_VERIFICATION);
        if (otpOpt.isEmpty()) return false;

        OTP otp = otpOpt.get();
        if (otp.getExpiresAt().isBefore(java.time.LocalDateTime.now())) return false;

        // mark used and verify user
        otpService.markUsed(otp);
        User user = otp.getUser();
        user.setEmailVerified(true);
        userRepository.save(user);
        return true;
    }

    public void resendVerificationOtp(String email) {
        User user = userRepository.findByEmail(email).orElseThrow(() -> new RuntimeException("User not found"));
        OTP otp = otpService.generateOTP(user, OTPPurpose.EMAIL_VERIFICATION, 15);
        emailService.sendSimpleMessage(user.getEmail(), "Verify your email - Resend", "Your code: " + otp.getOtpCode());
    }

    // DTO
    public record LoginResult(String token, boolean emailVerified) {}
}
