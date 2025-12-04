package com.gateway.auth.security;

import com.gateway.auth.exception.RateLimitExceededException;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;

@Component
@Slf4j
public class RateLimitingFilter extends OncePerRequestFilter {

    // Cache for tracking request counts per IP
    private final Cache<String, AtomicInteger> loginAttempts = Caffeine.newBuilder()
            .expireAfterWrite(Duration.ofMinutes(15))
            .build();

    private final Cache<String, AtomicInteger> registrationAttempts = Caffeine.newBuilder()
            .expireAfterWrite(Duration.ofHours(1))
            .build();

    private final Cache<String, AtomicInteger> otpAttempts = Caffeine.newBuilder()
            .expireAfterWrite(Duration.ofHours(1))
            .build();

    private static final int MAX_LOGIN_ATTEMPTS = 10;
    private static final int MAX_REGISTRATION_ATTEMPTS = 5;
    private static final int MAX_OTP_ATTEMPTS = 10;

    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                    HttpServletResponse response, 
                                    FilterChain filterChain) throws ServletException, IOException {
        
        String ipAddress = extractIpAddress(request);
        String requestUri = request.getRequestURI();
        String method = request.getMethod();

        // Only apply rate limiting to POST requests on auth endpoints
        if ("POST".equals(method)) {
            try {
                if (requestUri.contains("/api/auth/login")) {
                    checkRateLimit(loginAttempts, ipAddress, MAX_LOGIN_ATTEMPTS, "login");
                } else if (requestUri.contains("/api/auth/register")) {
                    checkRateLimit(registrationAttempts, ipAddress, MAX_REGISTRATION_ATTEMPTS, "registration");
                } else if (requestUri.contains("/api/auth/resend-otp") || requestUri.contains("/api/auth/verify-email")) {
                    checkRateLimit(otpAttempts, ipAddress, MAX_OTP_ATTEMPTS, "OTP");
                }
            } catch (RateLimitExceededException e) {
                response.setStatus(429); // Too Many Requests
                response.setContentType("application/json");
                response.getWriter().write(String.format(
                    "{\"error\": \"%s\", \"retryAfter\": %d}", 
                    e.getMessage(), 
                    e.getRetryAfterSeconds()
                ));
                log.warn("Rate limit exceeded for IP {} on endpoint {}", ipAddress, requestUri);
                return;
            }
        }

        filterChain.doFilter(request, response);
    }

    private void checkRateLimit(Cache<String, AtomicInteger> cache, String key, int maxAttempts, String action) {
        AtomicInteger attempts = cache.get(key, k -> new AtomicInteger(0));
        
        if (attempts.incrementAndGet() > maxAttempts) {
            long retryAfter = action.equals("login") ? 900 : 3600; // 15 min or 1 hour
            throw new RateLimitExceededException(
                "Too many " + action + " attempts. Please try again later.",
                retryAfter
            );
        }
    }

    private String extractIpAddress(HttpServletRequest request) {
        String ipAddress = request.getHeader("X-Forwarded-For");
        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getHeader("X-Real-IP");
        }
        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getRemoteAddr();
        }

        if (ipAddress != null && ipAddress.contains(",")) {
            ipAddress = ipAddress.split(",")[0].trim();
        }

        return ipAddress != null ? ipAddress : "unknown";
    }
}
