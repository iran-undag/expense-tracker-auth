package com.example.auth.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
@Slf4j
public class RateLimitService {

    private static final String RATE_LIMIT_PREFIX = "auth:rate_limit:";

    private final StringRedisTemplate redisTemplate;
    private final boolean enabled;
    private final int requestsPerMinute;

    public RateLimitService(
            StringRedisTemplate redisTemplate,
            @Value("${app.security.rate-limiting.enabled:true}") boolean enabled,
            @Value("${app.security.rate-limiting.requests-per-minute:100}") int requestsPerMinute) {
        this.redisTemplate = redisTemplate;
        this.enabled = enabled;
        this.requestsPerMinute = requestsPerMinute;
    }

    public boolean allowRequest(String identifier) {
        if (!enabled) {
            return true;
        }

        String key = RATE_LIMIT_PREFIX + identifier;
        Long count = redisTemplate.opsForValue().increment(key);
        if (count != null && count == 1L) {
            redisTemplate.expire(key, Duration.ofMinutes(1));
        }

        boolean allowed = count == null || count <= requestsPerMinute;
        if (!allowed) {
            log.warn("Rate limit exceeded for {}", identifier);
        }
        return allowed;
    }
}
