package com.example.auth.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class StartupValidator implements ApplicationRunner {

    private final String allowedOrigins;
    private final boolean requireExplicitOrigins;
    private final boolean accountLockoutEnabled;
    private final boolean rateLimitingEnabled;

    public StartupValidator(
            @Value("${app.cors.allowed-origin-patterns:}") String allowedOrigins,
            @Value("${app.security.cors.require-explicit-origins:false}") boolean requireExplicitOrigins,
            @Value("${app.security.account-lockout.enabled:true}") boolean accountLockoutEnabled,
            @Value("${app.security.rate-limiting.enabled:true}") boolean rateLimitingEnabled) {
        this.allowedOrigins = allowedOrigins;
        this.requireExplicitOrigins = requireExplicitOrigins;
        this.accountLockoutEnabled = accountLockoutEnabled;
        this.rateLimitingEnabled = rateLimitingEnabled;
    }

    @Override
    public void run(ApplicationArguments args) {
        validateCors();
        validateProductionSecurityFlags();
    }

    private void validateCors() {
        if (allowedOrigins == null || allowedOrigins.isBlank()) {
            if (requireExplicitOrigins) {
                throw new IllegalStateException("CORS allowed origins must be configured in production.");
            }
            return;
        }
        CorsConfig.parseAllowedOrigins(allowedOrigins);
        log.info("CORS configuration validated for origins: {}", allowedOrigins);
    }

    private void validateProductionSecurityFlags() {
        if (!requireExplicitOrigins) {
            return;
        }
        if (!accountLockoutEnabled) {
            throw new IllegalStateException("Account lockout must be enabled in production.");
        }
        if (!rateLimitingEnabled) {
            throw new IllegalStateException("Rate limiting must be enabled in production.");
        }
    }
}
