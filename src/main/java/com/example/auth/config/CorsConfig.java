package com.example.auth.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.util.Arrays;
import java.util.List;

@Configuration
public class CorsConfig {

    @Bean
    public CorsConfigurationSource corsConfigurationSource(
            @Value("${app.cors.allowed-origin-patterns:http://localhost:5173}") String allowedOriginPatterns) {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        List<String> allowedOrigins = parseAllowedOrigins(allowedOriginPatterns);
        
        config.setAllowCredentials(true);
        config.setAllowedOrigins(allowedOrigins);
        config.setAllowedHeaders(List.of("Origin", "Content-Type", "Accept", "Authorization", "X-Requested-With",
                CorrelationId.HEADER_NAME));
        config.setExposedHeaders(List.of(CorrelationId.HEADER_NAME));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));

        source.registerCorsConfiguration("/api/**", config);
        source.registerCorsConfiguration("/actuator/**", config);
        source.registerCorsConfiguration("/connect/**", config);
        source.registerCorsConfiguration("/oauth2/**", config);
        source.registerCorsConfiguration("/userinfo", config);
        source.registerCorsConfiguration("/.well-known/**", config);
        return source;
    }

    @Bean
    public CorsFilter corsFilter(CorsConfigurationSource corsConfigurationSource) {
        return new CorsFilter(corsConfigurationSource);
    }

    static List<String> parseAllowedOrigins(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("CORS allowed origins must not be blank.");
        }
        List<String> origins = Arrays.stream(value.split(","))
            .map(String::trim)
            .filter(origin -> !origin.isBlank())
            .toList();
        if (origins.isEmpty()) {
            throw new IllegalArgumentException("CORS allowed origins must include at least one origin.");
        }
        if (origins.stream().anyMatch(origin -> origin.contains("*"))) {
            throw new IllegalArgumentException("Wildcard CORS origins are not allowed.");
        }
        return origins;
    }
}
