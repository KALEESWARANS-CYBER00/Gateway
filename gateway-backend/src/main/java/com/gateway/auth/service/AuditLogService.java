package com.gateway.auth.service;

import com.gateway.auth.model.AuditAction;
import com.gateway.auth.model.AuditLog;
import com.gateway.auth.repository.AuditLogRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuditLogService {

    private final AuditLogRepository auditLogRepository;

    @Async
    @Transactional
    public void logAuthEvent(Long userId, String email, AuditAction action, 
                             boolean success, String failureReason, 
                             String ipAddress, String userAgent) {
        try {
            AuditLog auditLog = AuditLog.builder()
                    .userId(userId)
                    .email(email)
                    .action(action)
                    .success(success)
                    .failureReason(failureReason)
                    .ipAddress(ipAddress)
                    .userAgent(userAgent)
                    .timestamp(LocalDateTime.now())
                    .build();

            auditLogRepository.save(auditLog);
            log.debug("Audit log created: action={}, email={}, success={}", action, email, success);
        } catch (Exception e) {
            log.error("Failed to create audit log: {}", e.getMessage());
        }
    }

    @Async
    @Transactional
    public void logAuthEvent(Long userId, String email, AuditAction action, 
                             boolean success, HttpServletRequest request) {
        String ipAddress = extractIpAddress(request);
        String userAgent = request.getHeader("User-Agent");
        logAuthEvent(userId, email, action, success, null, ipAddress, userAgent);
    }

    @Async
    @Transactional
    public void logAuthFailure(String email, AuditAction action, String failureReason, 
                               HttpServletRequest request) {
        String ipAddress = extractIpAddress(request);
        String userAgent = request.getHeader("User-Agent");
        logAuthEvent(null, email, action, false, failureReason, ipAddress, userAgent);
    }

    public String extractIpAddress(HttpServletRequest request) {
        if (request == null) {
            return "unknown";
        }

        String ipAddress = request.getHeader("X-Forwarded-For");
        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getHeader("X-Real-IP");
        }
        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getRemoteAddr();
        }

        // Handle multiple IPs in X-Forwarded-For
        if (ipAddress != null && ipAddress.contains(",")) {
            ipAddress = ipAddress.split(",")[0].trim();
        }

        return ipAddress != null ? ipAddress : "unknown";
    }
}
