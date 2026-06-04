package com.example.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Dedicated configuration for the password encoder bean.
 * Kept in a separate class to avoid circular dependency:
 * SecurityConfig -> OAuth2UserService -> AuthServiceImpl -> PasswordEncoder (back to SecurityConfig)
 */
@Configuration
public class PasswordEncoderConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
