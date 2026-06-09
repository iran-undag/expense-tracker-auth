package com.example.auth.config;

import com.example.auth.model.AppUser;
import com.example.auth.model.AuthProvider;
import com.example.auth.model.Role;
import com.example.auth.repository.AppUserRepository;
import com.example.auth.repository.RoleRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.DefaultApplicationArguments;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AdminAccountInitializerTest {

    @Mock
    private AppUserRepository userRepository;

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Test
    void run_CreatesAdminWhenMissing() {
        Role adminRole = Role.builder().id(1L).name("ADMIN").build();
        when(roleRepository.findByName("ADMIN")).thenReturn(Optional.of(adminRole));
        when(userRepository.findByEmail("admin@example.com")).thenReturn(Optional.empty());
        when(passwordEncoder.encode("StrongPassword123!")).thenReturn("encoded");

        initializer(true, false).run(new DefaultApplicationArguments());

        ArgumentCaptor<AppUser> userCaptor = ArgumentCaptor.forClass(AppUser.class);
        verify(userRepository).save(userCaptor.capture());
        AppUser saved = userCaptor.getValue();

        assertEquals("admin@example.com", saved.getEmail());
        assertEquals("encoded", saved.getPasswordHash());
        assertTrue(saved.isEnabled());
        assertTrue(saved.isEmailVerified());
        assertEquals(AuthProvider.LOCAL, saved.getAuthProvider());
        assertTrue(saved.getRoles().stream().anyMatch(role -> "ADMIN".equals(role.getName())));
    }

    @Test
    void run_PromotesExistingUserWithoutResettingPassword() {
        Role adminRole = Role.builder().id(1L).name("ADMIN").build();
        Role userRole = Role.builder().id(2L).name("USER").build();
        AppUser existing = AppUser.builder()
            .email("admin@example.com")
            .passwordHash("original")
            .enabled(false)
            .emailVerified(false)
            .verificationToken("token")
            .authProvider(AuthProvider.LOCAL)
            .roles(new HashSet<>(Set.of(userRole)))
            .build();

        when(roleRepository.findByName("ADMIN")).thenReturn(Optional.of(adminRole));
        when(userRepository.findByEmail("admin@example.com")).thenReturn(Optional.of(existing));

        initializer(true, false).run(new DefaultApplicationArguments());

        assertEquals("original", existing.getPasswordHash());
        assertTrue(existing.isEnabled());
        assertTrue(existing.isEmailVerified());
        assertNull(existing.getVerificationToken());
        assertTrue(existing.getRoles().stream().anyMatch(role -> "ADMIN".equals(role.getName())));
        verify(passwordEncoder, never()).encode(any());
        verify(userRepository).save(existing);
    }

    @Test
    void run_DoesNotUpdateExistingAdminWhenUnchanged() {
        Role adminRole = Role.builder().id(1L).name("ADMIN").build();
        AppUser existing = AppUser.builder()
            .email("admin@example.com")
            .passwordHash("original")
            .enabled(true)
            .emailVerified(true)
            .authProvider(AuthProvider.LOCAL)
            .roles(new HashSet<>(Set.of(adminRole)))
            .build();

        when(roleRepository.findByName("ADMIN")).thenReturn(Optional.of(adminRole));
        when(userRepository.findByEmail("admin@example.com")).thenReturn(Optional.of(existing));

        initializer(true, false).run(new DefaultApplicationArguments());

        verify(userRepository, never()).save(any(AppUser.class));
        verify(passwordEncoder, never()).encode(any());
    }

    @Test
    void run_ResetsPasswordOnlyWhenConfigured() {
        Role adminRole = Role.builder().id(1L).name("ADMIN").build();
        AppUser existing = AppUser.builder()
            .email("admin@example.com")
            .passwordHash("original")
            .enabled(true)
            .emailVerified(true)
            .authProvider(AuthProvider.LOCAL)
            .roles(new HashSet<>(Set.of(adminRole)))
            .build();

        when(roleRepository.findByName("ADMIN")).thenReturn(Optional.of(adminRole));
        when(userRepository.findByEmail("admin@example.com")).thenReturn(Optional.of(existing));
        when(passwordEncoder.encode("StrongPassword123!")).thenReturn("new-encoded");

        initializer(true, true).run(new DefaultApplicationArguments());

        assertEquals("new-encoded", existing.getPasswordHash());
        verify(userRepository).save(existing);
    }

    @Test
    void run_DoesNothingWhenDisabled() {
        initializer(false, false).run(new DefaultApplicationArguments());

        verifyNoInteractions(userRepository, roleRepository, passwordEncoder);
    }

    private AdminAccountInitializer initializer(boolean enabled, boolean resetPassword) {
        return new AdminAccountInitializer(
            userRepository,
            roleRepository,
            passwordEncoder,
            enabled,
            "admin@example.com",
            "StrongPassword123!",
            "Administrator",
            resetPassword
        );
    }
}
