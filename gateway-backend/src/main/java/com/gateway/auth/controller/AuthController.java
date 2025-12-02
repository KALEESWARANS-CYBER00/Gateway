package com.gateway.auth.controller;

import com.gateway.auth.service.AuthService;
import com.gateway.auth.service.AuthService.LoginResult;
import com.gateway.auth.model.OTPPurpose;
import lombok.*;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest req) {
        try {
            authService.register(req.email(), req.password(), req.name());
            return ResponseEntity.ok(new GenericResponse("User registered. OTP sent to email."));
        } catch (RuntimeException ex) {
            return ResponseEntity.badRequest().body(new ErrorResponse(ex.getMessage()));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest req) {
        try {
            LoginResult res = authService.login(req.email(), req.password());
            if (!res.emailVerified()) {
                return ResponseEntity.status(403).body(new ErrorResponse("Email not verified. Please verify your email."));
            }
            return ResponseEntity.ok(new AuthResponse("Login successful", res.token()));
        } catch (RuntimeException ex) {
            return ResponseEntity.status(401).body(new ErrorResponse("Invalid credentials"));
        }
    }

    @PostMapping("/verify-email")
    public ResponseEntity<?> verifyEmail(@RequestParam String otp) {
        boolean ok = authService.verifyEmailOTP(otp);
        return ok ? ResponseEntity.ok(new GenericResponse("Email verified")) : ResponseEntity.badRequest().body(new ErrorResponse("Invalid or expired OTP"));
    }

    @PostMapping("/resend-otp")
    public ResponseEntity<?> resendOtp(@RequestParam String email) {
        try {
            authService.resendVerificationOtp(email);
            return ResponseEntity.ok(new GenericResponse("OTP resent"));
        } catch (RuntimeException ex) {
            return ResponseEntity.badRequest().body(new ErrorResponse(ex.getMessage()));
        }
    }

    // DTOs
    public record RegisterRequest(String email, String password, String name) {}
    public record LoginRequest(String email, String password) {}

    @Data @AllArgsConstructor
    static class GenericResponse { private String message; }

    @Data @AllArgsConstructor
    static class AuthResponse { private String message; private String token; }

    @Data @AllArgsConstructor
    static class ErrorResponse { private String error; }
}
