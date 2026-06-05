package com.example.auth.config;

import com.example.auth.service.UserPrincipal;
import com.example.auth.service.CustomOidcUserPrincipal;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.util.StreamUtils;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Configuration
public class AuthorizationServerConfig {

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
            // Enable OpenID Connect 1.0 + dynamic client registration inside oidc()
            .oidc(oidc -> oidc
                .clientRegistrationEndpoint(Customizer.withDefaults())
            );

        http
            // Redirect to formLogin login page if not authenticated on authorization endpoints
            .exceptionHandling(exceptions -> exceptions
                .defaultAuthenticationEntryPointFor(
                    new LoginUrlAuthenticationEntryPoint("/login"),
                    new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                )
            )
            // Accept access tokens for Dynamic Client Registration
            .oauth2ResourceServer(resourceServer -> resourceServer.jwt(Customizer.withDefaults()));

        return http.build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        // Dynamic client registration stores clients in jdbc-backed repository
        JdbcRegisteredClientRepository repository = new JdbcRegisteredClientRepository(jdbcTemplate);
        
        // We will seed a default developer client if empty during start
        // This makes postman/swagger testing of the auth server extremely convenient
        return repository;
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource(
            ResourceLoader resourceLoader,
            @Value("${app.auth.jwk-set-location:}") String jwkSetLocation) {
        JWKSet configuredJwkSet = loadConfiguredJwkSet(resourceLoader, jwkSetLocation);
        JWKSet jwkSet = configuredJwkSet != null ? configuredJwkSet : new JWKSet(generateRsaJwk());
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    private static JWKSet loadConfiguredJwkSet(ResourceLoader resourceLoader, String jwkSetLocation) {
        if (!StringUtils.hasText(jwkSetLocation)) {
            return null;
        }

        try {
            Resource resource = resourceLoader.getResource(jwkSetLocation);
            String jwkSetJson = StreamUtils.copyToString(resource.getInputStream(), StandardCharsets.UTF_8);
            return JWKSet.parse(jwkSetJson);
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to load configured JWK set from " + jwkSetLocation, ex);
        }
    }

    private static RSAKey generateRsaJwk() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        return new RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(UUID.randomUUID().toString())
            .build();
    }

    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings(
            @Value("${app.auth.issuer-uri:http://localhost:9000}") String issuerUri) {
        return AuthorizationServerSettings.builder()
            // JWK set endpoint will be hosted at issuer + '/oauth2/jwks'
            .issuer(issuerUri)
            .build();
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return context -> {
            if ("access_token".equals(context.getTokenType().getValue())) {
                Object principal = context.getPrincipal().getPrincipal();
                
                Long userId = null;
                String email = null;
                Set<String> roles = null;

                if (principal instanceof UserPrincipal userPrincipal) {
                    userId = userPrincipal.getId();
                    email = userPrincipal.getEmail();
                    roles = userPrincipal.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toSet());
                } else if (principal instanceof CustomOidcUserPrincipal oidcPrincipal) {
                    userId = oidcPrincipal.getUser().getId();
                    email = oidcPrincipal.getUser().getEmail();
                    roles = oidcPrincipal.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toSet());
                }

                if (userId != null) {
                    context.getClaims()
                        .claim("userId", userId)
                        .claim("email", email)
                        .claim("roles", roles);
                }
            }
        };
    }
}
