package com.gateway.auth.service;

import com.gateway.auth.model.RefreshToken;
import com.gateway.auth.model.User;
import com.gateway.auth.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

    @Value("${jwt.refresh-expiration:604800000}") // 7 days default
    private long refreshExpirationMs;

    @Transactional
    public RefreshToken createRefreshToken(User user, String ipAddress, String userAgent) {
        // Limit active tokens per user (max 5 devices)
        long activeTokens = refreshTokenRepository.countActiveTokensByUser(user, LocalDateTime.now());
        if (activeTokens >= 5) {
            // Revoke oldest token
            var tokens = refreshTokenRepository.findByUserAndIsRevokedFalse(user);
            if (!tokens.isEmpty()) {
                RefreshToken oldest = tokens.get(0);
                oldest.setRevoked(true);
                refreshTokenRepository.save(oldest);
            }
        }

        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .token(UUID.randomUUID().toString())
                .expiresAt(LocalDateTime.now().plusSeconds(refreshExpirationMs / 1000))
                .isRevoked(false)
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .build();

        return refreshTokenRepository.save(refreshToken);
    }

    @Transactional(readOnly = true)
    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    @Transactional
    public void revokeToken(String token) {
        refreshTokenRepository.findByToken(token).ifPresent(rt -> {
            rt.setRevoked(true);
            refreshTokenRepository.save(rt);
            log.info("Refresh token revoked: {}", token.substring(0, 8) + "...");
        });
    }

    @Transactional
    public void revokeAllUserTokens(User user) {
        refreshTokenRepository.revokeAllUserTokens(user);
        log.info("All refresh tokens revoked for user: {}", user.getEmail());
    }

    @Transactional
    @Scheduled(cron = "0 0 2 * * ?") // Run daily at 2 AM
    public void cleanupExpiredTokens() {
        refreshTokenRepository.deleteExpiredTokens(LocalDateTime.now());
        log.info("Expired refresh tokens cleaned up");
    }

    public boolean validateRefreshToken(RefreshToken token) {
        if (token == null) {
            return false;
        }
        return token.isValid();
    }
}
