package com.example.auth.config;

import com.example.auth.exception.EmailNotVerifiedException;
import com.example.auth.model.AppUser;
import com.example.auth.repository.AppUserRepository;
import com.example.auth.security.RateLimitFilter;
import com.example.auth.security.TokenBlacklistFilter;
import com.example.auth.service.AuditService;
import com.example.auth.service.CustomOAuth2UserService;
import com.example.auth.service.CustomOidcUserService;
import com.example.auth.service.LoginAttemptService;
import com.example.auth.service.UserPrincipal;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
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
    private final LoginAttemptService loginAttemptService;
    private final RateLimitFilter rateLimitFilter;
    private final TokenBlacklistFilter tokenBlacklistFilter;
    private final CorrelationIdFilter correlationIdFilter;
    private final AuditService auditService;

    @Value("${spring.h2.console.enabled:false}")
    private boolean h2ConsoleEnabled;

    @Value("${app.frontend.base-url:http://localhost:5173}")
    private String frontendBaseUrl;

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        SavedRequestAwareAuthenticationSuccessHandler savedRequestSuccessHandler =
            new SavedRequestAwareAuthenticationSuccessHandler();
        savedRequestSuccessHandler.setDefaultTargetUrl(frontendBaseUrl);

        http
            .addFilterBefore(correlationIdFilter, UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(rateLimitFilter, UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(tokenBlacklistFilter, UsernamePasswordAuthenticationFilter.class)
            .csrf(csrf -> csrf
                // Disable CSRF for REST APIs, keep enabled for server-rendered forms by permitting selectively
                .ignoringRequestMatchers("/api/auth/**", "/connect/register", "/h2-console/**")
            )
            .cors(Customizer.withDefaults())
            .authorizeHttpRequests(authorize -> authorize
                // REST auth API endpoints
                .requestMatchers("/api/auth/signup", "/api/auth/login", "/api/auth/verify-email", "/api/auth/resend-verification", "/api/auth/logout").permitAll()
                // Thymeleaf Page UI routes
                .requestMatchers("/login", "/signup", "/verify-email", "/css/**", "/js/**", "/favicon.ico").permitAll()
                // Allow Spring Boot's error endpoint to render OAuth2 authorization errors instead of saving /error as a post-login target
                .requestMatchers("/error").permitAll()
                // Health checks remain public; diagnostics and docs require admin access.
                .requestMatchers("/actuator/health", "/actuator/health/**").permitAll()
                .requestMatchers("/h2-console/**").permitAll()
                .requestMatchers("/actuator/**", "/swagger-ui/**", "/v3/api-docs/**").hasRole("ADMIN")
                // Admin management
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                // All other requests require authentication
                .anyRequest().authenticated()
            )
            .formLogin(formLogin -> formLogin
                .loginPage("/login")
                .usernameParameter("email")
                .passwordParameter("password")
                .failureHandler((request, response, exception) -> {
                    String email = request.getParameter("email");
                    loginAttemptService.loginFailed(email);
                    auditService.record("AUTHENTICATION", email, "LOGIN", "FAILURE");
                    if (email != null && loginAttemptService.isAccountLocked(email)) {
                        response.sendRedirect("/login?error=locked&minutes=" + loginAttemptService.getMinutesRemaining(email));
                        return;
                    }
                    response.sendRedirect("/login?error=invalid");
                })
                .successHandler((request, response, authentication) -> {
                    loginAttemptService.loginSucceeded(authentication.getName());
                    auditService.record("AUTHENTICATION", authentication.getName(), "LOGIN", "SUCCESS");
                    savedRequestSuccessHandler.onAuthenticationSuccess(request, response, authentication);
                })
                .permitAll()
            )
            .oauth2Login(oauth2 -> oauth2
                .loginPage("/login")
                .userInfoEndpoint(userInfo -> userInfo
                    .userService(customOAuth2UserService)
                    .oidcUserService(customOidcUserService)
                )
                .defaultSuccessUrl(frontendBaseUrl, false)
            )
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?logout")
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .deleteCookies("JSESSIONID")
                .permitAll()
            )
            .oauth2ResourceServer(resourceServer -> resourceServer.jwt(Customizer.withDefaults()))
            // Enable H2 console frame layout display
            .headers(headers -> headers
                .httpStrictTransportSecurity(hsts -> hsts
                    .includeSubDomains(true)
                    .preload(true)
                    .maxAgeInSeconds(31536000))
                .contentSecurityPolicy(csp -> csp
                    .policyDirectives(contentSecurityPolicy()))
                .contentTypeOptions(Customizer.withDefaults())
                .referrerPolicy(referrer -> referrer.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER))
                .xssProtection(xss -> xss.headerValue(XXssProtectionHeaderWriter.HeaderValue.ENABLED_MODE_BLOCK))
                .frameOptions(frameOptions -> {
                    if (h2ConsoleEnabled) {
                        frameOptions.sameOrigin();
                    } else {
                        frameOptions.deny();
                    }
                })
            );

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return email -> {
            if (loginAttemptService.isAccountLocked(email)) {
                throw new LockedException("Account is temporarily locked. Please try again later.");
            }

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

    private String contentSecurityPolicy() {
        String frameAncestors = h2ConsoleEnabled ? "'self'" : "'none'";
        return "default-src 'self'; "
            + "script-src 'self' 'unsafe-inline'; "
            + "style-src 'self' 'unsafe-inline'; "
            + "img-src 'self' data: https:; "
            + "font-src 'self'; "
            + "connect-src 'self'; "
            + "frame-ancestors " + frameAncestors + "; "
            + "base-uri 'self'; "
            + "form-action 'self'";
    }
}
