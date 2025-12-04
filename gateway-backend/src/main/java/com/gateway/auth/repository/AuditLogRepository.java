package com.gateway.auth.repository;

import com.gateway.auth.model.AuditAction;
import com.gateway.auth.model.AuditLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {

    List<AuditLog> findByUserIdOrderByTimestampDesc(Long userId);

    List<AuditLog> findByActionAndTimestampAfter(AuditAction action, LocalDateTime after);

    List<AuditLog> findByUserIdAndActionOrderByTimestampDesc(Long userId, AuditAction action);

    List<AuditLog> findByIpAddressAndActionAndTimestampAfter(String ipAddress, AuditAction action, LocalDateTime after);
}
