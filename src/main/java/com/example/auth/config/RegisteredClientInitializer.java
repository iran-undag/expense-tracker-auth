package com.example.auth.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.UUID;

@Component
public class RegisteredClientInitializer implements ApplicationRunner {

    private final RegisteredClientRepository registeredClientRepository;
    private final PasswordEncoder passwordEncoder;
    private final boolean enabled;
    private final String clientId;
    private final String clientSecret;
    private final boolean publicClient;
    private final String redirectUris;
    private final String postLogoutRedirectUris;
    private final String scopes;

    public RegisteredClientInitializer(
            RegisteredClientRepository registeredClientRepository,
            PasswordEncoder passwordEncoder,
            @Value("${app.auth.client.enabled:false}") boolean enabled,
            @Value("${app.auth.client.client-id:expense-tracker-postman}") String clientId,
            @Value("${app.auth.client.client-secret:change-me-client-secret}") String clientSecret,
            @Value("${app.auth.client.public-client:false}") boolean publicClient,
            @Value("${app.auth.client.redirect-uris:https://oauth.pstmn.io/v1/callback}") String redirectUris,
            @Value("${app.auth.client.post-logout-redirect-uris:http://localhost:5173/logout}") String postLogoutRedirectUris,
            @Value("${app.auth.client.scopes:openid,profile}") String scopes) {
        this.registeredClientRepository = registeredClientRepository;
        this.passwordEncoder = passwordEncoder;
        this.enabled = enabled;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.publicClient = publicClient;
        this.redirectUris = redirectUris;
        this.postLogoutRedirectUris = postLogoutRedirectUris;
        this.scopes = scopes;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (!enabled) {
            return;
        }

        RegisteredClient existingClient = registeredClientRepository.findByClientId(clientId);
        String registrationId = existingClient != null ? existingClient.getId() : UUID.randomUUID().toString();
        registeredClientRepository.save(buildClient(registrationId));
    }

    private RegisteredClient buildClient(String registrationId) {
        RegisteredClient.Builder builder = RegisteredClient.withId(registrationId)
            .clientId(clientId)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN);

        if (publicClient) {
            builder
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .clientSettings(ClientSettings.builder()
                    .requireProofKey(true)
                    .requireAuthorizationConsent(false)
                    .build());
        } else {
            builder
                .clientSecret(passwordEncoder.encode(clientSecret))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build());
        }

        splitCsv(redirectUris).forEach(builder::redirectUri);
        splitCsv(postLogoutRedirectUris).forEach(builder::postLogoutRedirectUri);
        splitCsv(scopes).forEach(scope -> builder.scope(normalizeScope(scope)));

        return builder.build();
    }

    private static Iterable<String> splitCsv(String value) {
        return Arrays.stream(value.split(","))
            .map(String::trim)
            .filter(item -> !item.isBlank())
            .toList();
    }

    private static String normalizeScope(String scope) {
        if ("openid".equals(scope)) {
            return OidcScopes.OPENID;
        }
        if ("profile".equals(scope)) {
            return OidcScopes.PROFILE;
        }
        return scope;
    }
}
