package com.example.auth.service;

import com.example.auth.model.AuditLog;
import com.example.auth.repository.AuditLogRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuditService {

    private final AuditLogRepository auditLogRepository;
    private final ObjectProvider<HttpServletRequest> requestProvider;

    public void record(String eventType, String userEmail, String action, String status) {
        record(eventType, userEmail, action, null, null, status);
    }

    public void record(String eventType, String userEmail, String action, String resourceType, String resourceId, String status) {
        AuditLog entry = AuditLog.builder()
            .eventType(eventType)
            .userEmail(userEmail)
            .action(action)
            .resourceType(resourceType)
            .resourceId(resourceId)
            .status(status)
            .ipAddress(clientIp())
            .userAgent(userAgent())
            .build();

        auditLogRepository.save(entry);
        log.info("AUDIT event={} user={} action={} resourceType={} resourceId={} status={} ip={}",
            eventType, userEmail, action, resourceType, resourceId, status, entry.getIpAddress());
    }

    private String clientIp() {
        HttpServletRequest request = requestProvider.getIfAvailable();
        if (request == null) {
            return null;
        }
        String forwardedFor = request.getHeader("X-Forwarded-For");
        if (forwardedFor != null && !forwardedFor.isBlank()) {
            return forwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    private String userAgent() {
        HttpServletRequest request = requestProvider.getIfAvailable();
        return request != null ? request.getHeader("User-Agent") : null;
    }
}
