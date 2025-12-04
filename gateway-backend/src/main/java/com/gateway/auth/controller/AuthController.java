package com.gateway.auth.controller;

import com.gateway.auth.exception.AccountLockedException;
import com.gateway.auth.service.AuthService;
import com.gateway.auth.service.AuthService.LoginResult;
import com.gateway.auth.service.AuthService.TokenRefreshResult;
import com.gateway.auth.model.User;
import com.gateway.auth.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.*;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@CrossOrigin(origins = {"http://localhost:3000", "http://localhost:3001"})
public class AuthController {

    private final AuthService authService;
    private final UserRepository userRepository;

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest req, HttpServletRequest request) {
        try {
            authService.register(req.email(), req.password(), req.name(), request);
            return ResponseEntity.ok(new GenericResponse("User registered successfully. Please check your email for verification code."));
        } catch (Exception ex) {
            return ResponseEntity.badRequest().body(new ErrorResponse(ex.getMessage()));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest req, HttpServletRequest request) {
        try {
            LoginResult result = authService.login(req.email(), req.password(), request);
            
            if (!result.emailVerified()) {
                return ResponseEntity.status(403).body(new ErrorResponse(
                    result.message() != null ? result.message() : "Email not verified. Please verify your email first."
                ));
            }
            
            return ResponseEntity.ok(new LoginResponse(
                "Login successful",
                result.accessToken(),
                result.refreshToken()
            ));
        } catch (AccountLockedException ex) {
            return ResponseEntity.status(423).body(new AccountLockedResponse(
                ex.getMessage(),
                ex.getMinutesRemaining()
            ));
        } catch (Exception ex) {
            return ResponseEntity.status(401).body(new ErrorResponse("Invalid credentials"));
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestBody RefreshTokenRequest req, HttpServletRequest request) {
        try {
            TokenRefreshResult result = authService.refreshAccessToken(req.refreshToken(), request);
            return ResponseEntity.ok(new TokenRefreshResponse(
                "Token refreshed successfully",
                result.accessToken(),
                result.refreshToken()
            ));
        } catch (Exception ex) {
            return ResponseEntity.status(401).body(new ErrorResponse(ex.getMessage()));
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestBody RefreshTokenRequest req, HttpServletRequest request) {
        try {
            authService.logout(req.refreshToken(), request);
            return ResponseEntity.ok(new GenericResponse("Logged out successfully"));
        } catch (Exception ex) {
            return ResponseEntity.badRequest().body(new ErrorResponse(ex.getMessage()));
        }
    }

    @PostMapping("/verify-email")
    public ResponseEntity<?> verifyEmail(@RequestParam String otp, HttpServletRequest request) {
        boolean success = authService.verifyEmailOTP(otp, request);
        return success 
            ? ResponseEntity.ok(new GenericResponse("Email verified successfully"))
            : ResponseEntity.badRequest().body(new ErrorResponse("Invalid or expired OTP"));
    }

    @PostMapping("/resend-otp")
    public ResponseEntity<?> resendOtp(@RequestParam String email, HttpServletRequest request) {
        try {
            authService.resendVerificationOtp(email, request);
            return ResponseEntity.ok(new GenericResponse("Verification code resent to your email"));
        } catch (Exception ex) {
            return ResponseEntity.badRequest().body(new ErrorResponse(ex.getMessage()));
        }
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@Valid @RequestBody ForgotPasswordRequest req, HttpServletRequest request) {
        try {
            authService.requestPasswordReset(req.email(), request);
            return ResponseEntity.ok(new GenericResponse("Password reset link sent to your email"));
        } catch (Exception ex) {
            // Don't reveal if email exists for security
            return ResponseEntity.ok(new GenericResponse("If the email exists, a password reset link has been sent"));
        }
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestParam String otp, @Valid @RequestBody NewPasswordRequest req, HttpServletRequest request) {
        try {
            authService.resetPassword(otp, req.newPassword(), request);
            return ResponseEntity.ok(new GenericResponse("Password reset successful. You can now login with your new password."));
        } catch (Exception ex) {
            return ResponseEntity.badRequest().body(new ErrorResponse(ex.getMessage()));
        }
    }

    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser() {
        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth == null || !auth.isAuthenticated()) {
                return ResponseEntity.status(401).body(new ErrorResponse("Not authenticated"));
            }

            String email = auth.getName();
            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            return ResponseEntity.ok(new UserResponse(
                user.getId(),
                user.getEmail(),
                user.getName(),
                user.getRole().toString(),
                user.isEmailVerified(),
                user.getLastLoginAt(),
                user.getCreatedAt()
            ));
        } catch (Exception ex) {
            return ResponseEntity.badRequest().body(new ErrorResponse(ex.getMessage()));
        }
    }

    // DTOs
    public record RegisterRequest(
        @NotBlank(message = "Email is required")
        @Email(message = "Invalid email format")
        String email,
        
        @NotBlank(message = "Password is required")
        String password,
        
        @NotBlank(message = "Name is required")
        @Size(min = 2, max = 100, message = "Name must be between 2 and 100 characters")
        String name
    ) {}

    public record LoginRequest(
        @NotBlank(message = "Email is required")
        @Email(message = "Invalid email format")
        String email,
        
        @NotBlank(message = "Password is required")
        String password
    ) {}

    public record RefreshTokenRequest(
        @NotBlank(message = "Refresh token is required")
        String refreshToken
    ) {}

    public record ForgotPasswordRequest(
        @NotBlank(message = "Email is required")
        @Email(message = "Invalid email format")
        String email
    ) {}

    public record ResetPasswordRequest(
        @NotBlank(message = "Token is required")
        String token,
        
        @NotBlank(message = "New password is required")
        String newPassword
    ) {}

    public record NewPasswordRequest(
        @NotBlank(message = "New password is required")
        String newPassword
    ) {}

    @Data @AllArgsConstructor
    static class GenericResponse { 
        private String message; 
    }

    @Data @AllArgsConstructor
    static class LoginResponse { 
        private String message; 
        private String accessToken; 
        private String refreshToken; 
    }

    @Data @AllArgsConstructor
    static class TokenRefreshResponse { 
        private String message; 
        private String accessToken; 
        private String refreshToken; 
    }

    @Data @AllArgsConstructor
    static class AccountLockedResponse {
        private String message;
        private long minutesRemaining;
    }

    @Data @AllArgsConstructor
    static class ErrorResponse { 
        private String error; 
    }

    @Data @AllArgsConstructor
    static class UserResponse {
        private Long id;
        private String email;
        private String name;
        private String role;
        private boolean emailVerified;
        private java.time.LocalDateTime lastLoginAt;
        private java.time.LocalDateTime createdAt;
    }
}
