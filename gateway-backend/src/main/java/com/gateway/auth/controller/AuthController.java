package com.gateway.auth.controller;

import com.gateway.auth.service.AuthService;
import lombok.*;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@CrossOrigin(origins = "*") // ⚠️ Allow all for testing; restrict in production
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody AuthRequest request) {
        try {
            String token = authService.register(request.getEmail(), request.getPassword());
            return ResponseEntity.ok(new AuthResponse("User registered successfully", token));
        } catch (RuntimeException ex) {
            return ResponseEntity.badRequest().body(new ErrorResponse(ex.getMessage()));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthRequest request) {
        try {
            String token = authService.login(request.getEmail(), request.getPassword());
            return ResponseEntity.ok(new AuthResponse("Login successful", token));
        } catch (RuntimeException ex) {
            return ResponseEntity.status(401).body(new ErrorResponse("Invalid email or password"));
        }
    }

    @GetMapping("/hello")
    public ResponseEntity<String> hello() {
        return ResponseEntity.ok("Welcome, authenticated user!");
    }

    // ======== DTOs ========

    @Data
    static class AuthRequest {
        private String email;
        private String password;
    }

    @Data
    @AllArgsConstructor
    static class AuthResponse {
        private String message;
        private String token;
    }

    @Data
    @AllArgsConstructor
    static class ErrorResponse {
        private String error;
    }
}
