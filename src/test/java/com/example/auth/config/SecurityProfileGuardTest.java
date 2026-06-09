package com.example.auth.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.DefaultApplicationArguments;
import org.springframework.mock.env.MockEnvironment;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SecurityProfileGuardTest {

    @Test
    void run_ThrowsWhenNoSecurityProfileIsActive() {
        SecurityProfileGuard guard = guardWithProfiles();

        assertThrows(IllegalStateException.class, () -> guard.run(new DefaultApplicationArguments()));
    }

    @Test
    void run_AllowsDevProfile() {
        SecurityProfileGuard guard = guardWithProfiles("dev");

        assertDoesNotThrow(() -> guard.run(new DefaultApplicationArguments()));
    }

    @Test
    void run_AllowsProdProfile() {
        SecurityProfileGuard guard = guardWithProfiles("prod");

        assertDoesNotThrow(() -> guard.run(new DefaultApplicationArguments()));
    }

    @Test
    void run_ThrowsWhenDevAndProdProfilesAreBothActive() {
        SecurityProfileGuard guard = guardWithProfiles("dev", "prod");

        assertThrows(IllegalStateException.class, () -> guard.run(new DefaultApplicationArguments()));
    }

    private SecurityProfileGuard guardWithProfiles(String... profiles) {
        MockEnvironment environment = new MockEnvironment();
        environment.setActiveProfiles(profiles);
        return new SecurityProfileGuard(environment);
    }
}
