package com.example.auth.service;

import com.example.auth.config.oauth2.GoogleOAuth2UserInfo;
import com.example.auth.dto.SignupRequest;
import com.example.auth.exception.EmailAlreadyExistsException;
import com.example.auth.exception.TokenExpiredException;
import com.example.auth.model.AppUser;
import com.example.auth.model.AuthProvider;
import com.example.auth.model.Role;
import com.example.auth.repository.AppUserRepository;
import com.example.auth.repository.RoleRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class AuthServiceImplTest {

    @Mock
    private AppUserRepository userRepository;

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private EmailService emailService;

    @InjectMocks
    private AuthServiceImpl authService;

    private SignupRequest signupRequest;
    private Role userRole;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(authService, "verificationTokenExpirationHours", 24L);

        signupRequest = SignupRequest.builder()
            .email("test@example.com")
            .displayName("Test User")
            .password("Password123")
            .build();

        userRole = Role.builder()
            .id(1L)
            .name("USER")
            .build();
    }

    @Test
    void registerLocalUser_Success() {
        // Arrange
        when(userRepository.existsByEmail(signupRequest.getEmail())).thenReturn(false);
        when(roleRepository.findByName("USER")).thenReturn(Optional.of(userRole));
        when(passwordEncoder.encode(signupRequest.getPassword())).thenReturn("encodedPassword");
        
        when(userRepository.save(any(AppUser.class))).thenAnswer(invocation -> {
            AppUser user = invocation.getArgument(0);
            user.setId(10L);
            return user;
        });

        // Act
        AppUser registeredUser = authService.registerLocalUser(signupRequest);

        // Assert
        assertNotNull(registeredUser);
        assertEquals(10L, registeredUser.getId());
        assertEquals("test@example.com", registeredUser.getEmail());
        assertEquals("encodedPassword", registeredUser.getPasswordHash());
        assertFalse(registeredUser.isEnabled());
        assertFalse(registeredUser.isEmailVerified());
        assertNotNull(registeredUser.getVerificationToken());
        assertNotNull(registeredUser.getVerificationTokenCreatedAt());

        verify(emailService, times(1)).sendVerificationEmail(eq("test@example.com"), anyString());
    }

    @Test
    void registerLocalUser_ThrowsExceptionWhenEmailExists() {
        // Arrange
        when(userRepository.existsByEmail(signupRequest.getEmail())).thenReturn(true);

        // Act & Assert
        assertThrows(EmailAlreadyExistsException.class, () -> authService.registerLocalUser(signupRequest));
        verify(userRepository, never()).save(any(AppUser.class));
        verify(emailService, never()).sendVerificationEmail(anyString(), anyString());
    }

    @Test
    void verifyEmail_Success() {
        // Arrange
        AppUser unverifiedUser = AppUser.builder()
            .email("test@example.com")
            .enabled(false)
            .emailVerified(false)
            .verificationToken("token-123")
            .verificationTokenCreatedAt(LocalDateTime.now().minusHours(1))
            .build();

        when(userRepository.findByVerificationToken("token-123")).thenReturn(Optional.of(unverifiedUser));
        when(userRepository.save(any(AppUser.class))).thenReturn(unverifiedUser);

        // Act
        authService.verifyEmail("token-123");

        // Assert
        assertTrue(unverifiedUser.isEnabled());
        assertTrue(unverifiedUser.isEmailVerified());
        assertNull(unverifiedUser.getVerificationToken());
        assertNull(unverifiedUser.getVerificationTokenCreatedAt());
        verify(userRepository, times(1)).save(unverifiedUser);
    }

    @Test
    void verifyEmail_ThrowsWhenTokenExpired() {
        AppUser unverifiedUser = AppUser.builder()
            .email("test@example.com")
            .enabled(false)
            .emailVerified(false)
            .verificationToken("token-123")
            .verificationTokenCreatedAt(LocalDateTime.now().minusHours(25))
            .build();

        when(userRepository.findByVerificationToken("token-123")).thenReturn(Optional.of(unverifiedUser));
        when(userRepository.save(any(AppUser.class))).thenReturn(unverifiedUser);

        assertThrows(TokenExpiredException.class, () -> authService.verifyEmail("token-123"));
        assertFalse(unverifiedUser.isEnabled());
        assertFalse(unverifiedUser.isEmailVerified());
        assertNull(unverifiedUser.getVerificationToken());
        assertNull(unverifiedUser.getVerificationTokenCreatedAt());
        verify(userRepository).save(unverifiedUser);
    }

    @Test
    void findOrCreateOAuth2User_RejectsUnverifiedProviderEmail() {
        GoogleOAuth2UserInfo userInfo = new GoogleOAuth2UserInfo(Map.of(
            "sub", "google-123",
            "name", "Social User",
            "email", "social@example.com",
            "email_verified", false
        ));

        when(userRepository.findByAuthProviderAndProviderId(AuthProvider.GOOGLE, "google-123")).thenReturn(Optional.empty());

        assertThrows(IllegalArgumentException.class, () -> authService.findOrCreateOAuth2User("google", userInfo));
        verify(userRepository, never()).findByEmail(anyString());
        verify(userRepository, never()).save(any(AppUser.class));
    }

    @Test
    void findOrCreateOAuth2User_CreatesUserWhenProviderEmailIsVerified() {
        GoogleOAuth2UserInfo userInfo = new GoogleOAuth2UserInfo(Map.of(
            "sub", "google-123",
            "name", "Social User",
            "email", "social@example.com",
            "email_verified", true
        ));

        when(userRepository.findByAuthProviderAndProviderId(AuthProvider.GOOGLE, "google-123")).thenReturn(Optional.empty());
        when(userRepository.findByEmail("social@example.com")).thenReturn(Optional.empty());
        when(roleRepository.findByName("USER")).thenReturn(Optional.of(userRole));
        when(userRepository.save(any(AppUser.class))).thenAnswer(invocation -> invocation.getArgument(0));

        AppUser user = authService.findOrCreateOAuth2User("google", userInfo);

        assertEquals("social@example.com", user.getEmail());
        assertTrue(user.isEnabled());
        assertTrue(user.isEmailVerified());
        assertEquals(AuthProvider.GOOGLE, user.getAuthProvider());
        assertEquals("google-123", user.getProviderId());
    }
}
