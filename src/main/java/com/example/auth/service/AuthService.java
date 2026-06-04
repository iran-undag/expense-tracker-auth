package com.example.auth.service;

import com.example.auth.dto.SignupRequest;
import com.example.auth.model.AppUser;
import com.example.auth.config.oauth2.OAuth2UserInfo;

public interface AuthService {
    AppUser registerLocalUser(SignupRequest request);
    void verifyEmail(String token);
    void resendVerificationEmail(String email);
    AppUser findOrCreateOAuth2User(String registrationId, OAuth2UserInfo userInfo);
}
