package com.example.auth.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

@Service
@Slf4j
public class LoginAttemptService {

    private static final String ATTEMPTS_PREFIX = "auth:failed_attempts:";
    private static final String LOCKED_PREFIX = "auth:account_locked:";

    private final StringRedisTemplate redisTemplate;
    private final boolean enabled;
    private final int maxAttempts;
    private final int lockoutMinutes;

    public LoginAttemptService(
            StringRedisTemplate redisTemplate,
            @Value("${app.security.account-lockout.enabled:true}") boolean enabled,
            @Value("${app.security.account-lockout.max-attempts:5}") int maxAttempts,
            @Value("${app.security.account-lockout.duration-minutes:15}") int lockoutMinutes) {
        this.redisTemplate = redisTemplate;
        this.enabled = enabled;
        this.maxAttempts = maxAttempts;
        this.lockoutMinutes = lockoutMinutes;
    }

    public void loginSucceeded(String email) {
        if (!enabled || email == null || email.isBlank()) {
            return;
        }
        redisTemplate.delete(List.of(attemptsKey(email), lockedKey(email)));
    }

    public void loginFailed(String email) {
        if (!enabled || email == null || email.isBlank()) {
            return;
        }

        String attemptsKey = attemptsKey(email);
        Long attempts = redisTemplate.opsForValue().increment(attemptsKey);
        redisTemplate.expire(attemptsKey, Duration.ofMinutes(lockoutMinutes));

        if (attempts != null && attempts >= maxAttempts) {
            redisTemplate.opsForValue().set(lockedKey(email), "locked", Duration.ofMinutes(lockoutMinutes));
            log.warn("Account locked after {} failed login attempts for {}", attempts, normalize(email));
        }
    }

    public boolean isAccountLocked(String email) {
        if (!enabled || email == null || email.isBlank()) {
            return false;
        }
        return Boolean.TRUE.equals(redisTemplate.hasKey(lockedKey(email)));
    }

    public long getMinutesRemaining(String email) {
        if (!enabled || email == null || email.isBlank()) {
            return 0;
        }
        Long ttl = redisTemplate.getExpire(lockedKey(email), TimeUnit.MINUTES);
        return ttl != null && ttl > 0 ? ttl : 0;
    }

    private static String attemptsKey(String email) {
        return ATTEMPTS_PREFIX + normalize(email);
    }

    private static String lockedKey(String email) {
        return LOCKED_PREFIX + normalize(email);
    }

    private static String normalize(String email) {
        return email.trim().toLowerCase(Locale.ROOT);
    }
}
