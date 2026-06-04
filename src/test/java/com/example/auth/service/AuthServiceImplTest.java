package com.example.auth.service;

import com.example.auth.dto.SignupRequest;
import com.example.auth.exception.EmailAlreadyExistsException;
import com.example.auth.model.AppUser;
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
            .build();

        when(userRepository.findByVerificationToken("token-123")).thenReturn(Optional.of(unverifiedUser));
        when(userRepository.save(any(AppUser.class))).thenReturn(unverifiedUser);

        // Act
        authService.verifyEmail("token-123");

        // Assert
        assertTrue(unverifiedUser.isEnabled());
        assertTrue(unverifiedUser.isEmailVerified());
        assertNull(unverifiedUser.getVerificationToken());
        verify(userRepository, times(1)).save(unverifiedUser);
    }
}
