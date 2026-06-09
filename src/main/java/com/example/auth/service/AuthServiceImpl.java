package com.example.auth.service;

import com.example.auth.config.oauth2.OAuth2UserInfo;
import com.example.auth.dto.SignupRequest;
import com.example.auth.exception.EmailAlreadyExistsException;
import com.example.auth.exception.TokenExpiredException;
import com.example.auth.model.AppUser;
import com.example.auth.model.AuthProvider;
import com.example.auth.model.Role;
import com.example.auth.repository.AppUserRepository;
import com.example.auth.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.HashSet;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthServiceImpl implements AuthService {

    private final AppUserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;

    @Value("${app.security.verification-token-expiration-hours:24}")
    private long verificationTokenExpirationHours;

    @Override
    @Transactional
    public AppUser registerLocalUser(SignupRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new EmailAlreadyExistsException("An account with email " + request.getEmail() + " already exists.");
        }

        // Fetch default USER role
        Role userRole = roleRepository.findByName("USER")
            .orElseGet(() -> {
                log.warn("USER role not found in database, creating locally.");
                return roleRepository.save(Role.builder().name("USER").build());
            });

        String verificationToken = UUID.randomUUID().toString();

        AppUser user = AppUser.builder()
            .email(request.getEmail())
            .passwordHash(passwordEncoder.encode(request.getPassword()))
            .displayName(request.getDisplayName())
            .enabled(false) // Disabled until email verified
            .emailVerified(false)
            .verificationToken(verificationToken)
            .verificationTokenCreatedAt(LocalDateTime.now())
            .authProvider(AuthProvider.LOCAL)
            .roles(new HashSet<>(Collections.singleton(userRole)))
            .build();

        AppUser savedUser = userRepository.save(user);
        log.info("Registered new local user: {}", request.getEmail());

        // Send verification email
        emailService.sendVerificationEmail(savedUser.getEmail(), verificationToken);

        return savedUser;
    }

    @Override
    @Transactional
    public void verifyEmail(String token) {
        AppUser user = userRepository.findByVerificationToken(token)
            .orElseThrow(() -> new IllegalArgumentException("Invalid verification token."));

        if (isVerificationTokenExpired(user)) {
            user.setVerificationToken(null);
            user.setVerificationTokenCreatedAt(null);
            userRepository.save(user);
            throw new TokenExpiredException("Verification token has expired. Please request a new one.");
        }

        user.setEnabled(true);
        user.setEmailVerified(true);
        user.setVerificationToken(null);
        user.setVerificationTokenCreatedAt(null);
        userRepository.save(user);
        log.info("Email verified successfully for user: {}", user.getEmail());
    }

    @Override
    @Transactional
    public void resendVerificationEmail(String email) {
        AppUser user = userRepository.findByEmail(email)
            .orElseThrow(() -> new IllegalArgumentException("User with email " + email + " not found."));

        if (user.isEmailVerified()) {
            throw new IllegalStateException("Email is already verified.");
        }

        String verificationToken = UUID.randomUUID().toString();
        user.setVerificationToken(verificationToken);
        user.setVerificationTokenCreatedAt(LocalDateTime.now());
        userRepository.save(user);

        emailService.sendVerificationEmail(user.getEmail(), verificationToken);
        log.info("Verification email resent to user: {}", email);
    }

    private boolean isVerificationTokenExpired(AppUser user) {
        LocalDateTime createdAt = user.getVerificationTokenCreatedAt();
        if (createdAt == null) {
            return true;
        }
        return LocalDateTime.now().isAfter(createdAt.plusHours(verificationTokenExpirationHours));
    }

    @Override
    @Transactional
    public AppUser findOrCreateOAuth2User(String registrationId, OAuth2UserInfo userInfo) {
        AuthProvider authProvider = AuthProvider.valueOf(registrationId.toUpperCase());
        
        Optional<AppUser> userOptional = userRepository.findByAuthProviderAndProviderId(authProvider, userInfo.getId());
        
        if (userOptional.isPresent()) {
            // Existing social user, update profile if needed
            AppUser existingUser = userOptional.get();
            existingUser.setDisplayName(userInfo.getName());
            return userRepository.save(existingUser);
        }

        // Email from external provider
        String email = userInfo.getEmail();
        if (email == null || email.isBlank()) {
            // Fallback for providers that don't return public emails (like some GitHub accounts)
            email = userInfo.getId() + "@" + registrationId.toLowerCase() + ".com";
        }

        // If email already registered locally or via another provider
        Optional<AppUser> userByEmailOptional = userRepository.findByEmail(email);
        if (userByEmailOptional.isPresent()) {
            AppUser existingEmailUser = userByEmailOptional.get();
            log.warn("User with email {} already exists with provider {}. Linking new provider {}", 
                email, existingEmailUser.getAuthProvider(), registrationId);
            
            // Link new provider to existing user record
            existingEmailUser.setAuthProvider(authProvider);
            existingEmailUser.setProviderId(userInfo.getId());
            return userRepository.save(existingEmailUser);
        }

        // Completely new social user
        Role userRole = roleRepository.findByName("USER")
            .orElseGet(() -> roleRepository.save(Role.builder().name("USER").build()));

        AppUser newUser = AppUser.builder()
            .email(email)
            .displayName(userInfo.getName())
            .enabled(true) // Social users are trusted and pre-verified
            .emailVerified(true)
            .authProvider(authProvider)
            .providerId(userInfo.getId())
            .roles(new HashSet<>(Collections.singleton(userRole)))
            .build();

        AppUser savedUser = userRepository.save(newUser);
        log.info("Created new social login user: {} via {}", email, registrationId);
        return savedUser;
    }
}
