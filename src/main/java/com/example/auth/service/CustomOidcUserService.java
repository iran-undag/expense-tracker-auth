package com.example.auth.service;

import com.example.auth.config.oauth2.OAuth2UserInfo;
import com.example.auth.config.oauth2.OAuth2UserInfoFactory;
import com.example.auth.model.AppUser;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class CustomOidcUserService extends OidcUserService {

    private final AuthService authService;

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        OidcUser oidcUser = super.loadUser(userRequest);

        try {
            return processOidcUser(userRequest, oidcUser);
        } catch (AuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            log.error("Error processing OIDC user", ex);
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex);
        }
    }

    private OidcUser processOidcUser(OidcUserRequest userRequest, OidcUser oidcUser) {
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        
        OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(
            registrationId, 
            oidcUser.getAttributes()
        );

        AppUser user = authService.findOrCreateOAuth2User(registrationId, oAuth2UserInfo);
        
        // Wrap custom user details into OidcUser wrapper
        return new CustomOidcUserPrincipal(user, oidcUser);
    }
}
