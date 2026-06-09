package com.example.auth.repository;

import com.example.auth.model.AuditLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {
    List<AuditLog> findByUserEmailOrderByCreatedAtDesc(String userEmail);
    List<AuditLog> findByEventTypeOrderByCreatedAtDesc(String eventType);
    List<AuditLog> findByCreatedAtAfterOrderByCreatedAtDesc(LocalDateTime createdAt);
}
