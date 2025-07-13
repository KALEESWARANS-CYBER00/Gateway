package com.gateway.auth.service;
import com.gateway.auth.model.Role;
import com.gateway.auth.model.User;
import com.gateway.auth.repository.UserRepository;
import com.gateway.auth.security.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.*;
import org.springframework.security.core.AuthenticationException; // ✅ <-- Add this
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;


@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final CustomUserDetailsService userDetailsService;
    private final JwtUtil jwtUtil;

   public String register(String email, String password) {
    if (userRepository.findByEmail(email).isPresent()) {
        throw new RuntimeException("Email already exists");
    }

    User user = User.builder()
            .email(email)
            .password(passwordEncoder.encode(password))
            .role(Role.ADMIN)
            .build();

    userRepository.save(user);
    String token = jwtUtil.generateToken(user.getEmail());

    System.out.println("✅ Registration Token: " + token); // debug
    return token;
}

public String login(String email, String password) {
    try {
        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(email, password)
        );
        System.out.println("✅ Auth success for: " + email);
    } catch (AuthenticationException ex) {
        System.out.println("❌ Auth failed: " + ex.getMessage());
        throw new RuntimeException("Invalid credentials");
    }

    UserDetails userDetails = userDetailsService.loadUserByUsername(email);
    String token = jwtUtil.generateToken(userDetails.getUsername());

    System.out.println("✅ Login Token: " + token);
    return token;
}

}