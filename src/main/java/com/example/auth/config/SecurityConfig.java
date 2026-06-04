package com.example.auth.config;

import com.example.auth.exception.EmailNotVerifiedException;
import com.example.auth.model.AppUser;
import com.example.auth.repository.AppUserRepository;
import com.example.auth.service.CustomOAuth2UserService;
import com.example.auth.service.CustomOidcUserService;
import com.example.auth.service.UserPrincipal;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
@Slf4j
public class SecurityConfig {

    private final AppUserRepository userRepository;
    private final CustomOAuth2UserService customOAuth2UserService;
    private final CustomOidcUserService customOidcUserService;

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf
                // Disable CSRF for REST APIs, keep enabled for server-rendered forms by permitting selectively
                .ignoringRequestMatchers("/api/auth/**", "/connect/register", "/h2-console/**")
            )
            .cors(Customizer.withDefaults())
            .authorizeHttpRequests(authorize -> authorize
                // REST auth API endpoints
                .requestMatchers("/api/auth/signup", "/api/auth/login", "/api/auth/verify-email", "/api/auth/resend-verification").permitAll()
                // Thymeleaf Page UI routes
                .requestMatchers("/login", "/signup", "/verify-email", "/css/**", "/js/**", "/favicon.ico").permitAll()
                // H2 Dev Console & Actuator & API Docs
                .requestMatchers("/h2-console/**", "/actuator/**", "/swagger-ui/**", "/v3/api-docs/**").permitAll()
                // Admin management
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                // All other requests require authentication
                .anyRequest().authenticated()
            )
            .formLogin(formLogin -> formLogin
                .loginPage("/login")
                .usernameParameter("email")
                .passwordParameter("password")
                .defaultSuccessUrl("/", true)
                .permitAll()
            )
            .oauth2Login(oauth2 -> oauth2
                .loginPage("/login")
                .userInfoEndpoint(userInfo -> userInfo
                    .userService(customOAuth2UserService)
                    .oidcUserService(customOidcUserService)
                )
                .defaultSuccessUrl("/", true)
            )
            // Enable H2 console frame layout display
            .headers(headers -> headers
                .frameOptions(HeadersConfigurer.FrameOptionsConfig::disable)
                .xssProtection(xss -> xss.headerValue(XXssProtectionHeaderWriter.HeaderValue.ENABLED_MODE_BLOCK))
            );

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return email -> {
            AppUser user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));
            
            // Fail fast if local credentials login is attempted but email is not verified
            if (!user.isEmailVerified()) {
                log.warn("Login failed: email not verified for user {}", email);
                throw new EmailNotVerifiedException("Please verify your email before logging in.");
            }

            return new UserPrincipal(user);
        };
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }
}
