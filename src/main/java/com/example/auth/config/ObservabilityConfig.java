package com.example.auth.config;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ObservabilityConfig {

    @Bean
    public Counter successfulLoginsCounter(MeterRegistry registry) {
        return Counter.builder("auth.logins.success")
            .description("Number of successful local/social logins")
            .tag("service", "auth")
            .register(registry);
    }

    @Bean
    public Counter failedLoginsCounter(MeterRegistry registry) {
        return Counter.builder("auth.logins.failed")
            .description("Number of failed authentication attempts")
            .tag("service", "auth")
            .register(registry);
    }

    @Bean
    public Counter localSignupsCounter(MeterRegistry registry) {
        return Counter.builder("auth.signups.local")
            .description("Number of local registration attempts")
            .tag("service", "auth")
            .register(registry);
    }
}
