package com.example.auth.config;

import com.example.auth.model.AppUser;
import com.example.auth.model.AuthProvider;
import com.example.auth.model.Role;
import com.example.auth.repository.AppUserRepository;
import com.example.auth.repository.RoleRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.util.HashSet;
import java.util.Set;

@Component
@Slf4j
public class AdminAccountInitializer implements ApplicationRunner {

    private final AppUserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final boolean enabled;
    private final String email;
    private final String password;
    private final String displayName;
    private final boolean resetPassword;

    public AdminAccountInitializer(
            AppUserRepository userRepository,
            RoleRepository roleRepository,
            PasswordEncoder passwordEncoder,
            @Value("${app.admin.bootstrap.enabled:false}") boolean enabled,
            @Value("${app.admin.bootstrap.email:}") String email,
            @Value("${app.admin.bootstrap.password:}") String password,
            @Value("${app.admin.bootstrap.display-name:Administrator}") String displayName,
            @Value("${app.admin.bootstrap.reset-password:false}") boolean resetPassword) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.enabled = enabled;
        this.email = email;
        this.password = password;
        this.displayName = displayName;
        this.resetPassword = resetPassword;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        if (!enabled) {
            return;
        }
        validateConfiguration();

        Role adminRole = roleRepository.findByName("ADMIN")
            .orElseGet(() -> roleRepository.save(Role.builder().name("ADMIN").build()));

        userRepository.findByEmail(email)
            .ifPresentOrElse(
                existingUser -> updateExistingAdmin(existingUser, adminRole),
                () -> createAdmin(adminRole)
            );
    }

    private void createAdmin(Role adminRole) {
        AppUser admin = AppUser.builder()
            .email(email)
            .passwordHash(passwordEncoder.encode(password))
            .displayName(displayName)
            .enabled(true)
            .emailVerified(true)
            .authProvider(AuthProvider.LOCAL)
            .roles(new HashSet<>(Set.of(adminRole)))
            .build();

        userRepository.save(admin);
        log.warn("Bootstrap admin account created for {}", email);
    }

    private void updateExistingAdmin(AppUser user, Role adminRole) {
        boolean changed = false;

        if (user.getRoles().stream().noneMatch(role -> "ADMIN".equals(role.getName()))) {
            user.getRoles().add(adminRole);
            changed = true;
            log.warn("Existing account {} promoted to ADMIN by bootstrap configuration", email);
        }

        if (!user.isEnabled()) {
            user.setEnabled(true);
            changed = true;
        }

        if (!user.isEmailVerified()) {
            user.setEmailVerified(true);
            user.setVerificationToken(null);
            user.setVerificationTokenCreatedAt(null);
            changed = true;
        }

        if (resetPassword) {
            user.setPasswordHash(passwordEncoder.encode(password));
            changed = true;
            log.warn("Bootstrap admin password reset for {}", email);
        }

        if (changed) {
            userRepository.save(user);
        } else {
            log.info("Bootstrap admin account already exists for {}", email);
        }
    }

    private void validateConfiguration() {
        if (!StringUtils.hasText(email)) {
            throw new IllegalStateException("Admin bootstrap is enabled but app.admin.bootstrap.email is blank.");
        }
        if (!StringUtils.hasText(password)) {
            throw new IllegalStateException("Admin bootstrap is enabled but app.admin.bootstrap.password is blank.");
        }
        if (password.length() < 12) {
            throw new IllegalStateException("Admin bootstrap password must be at least 12 characters long.");
        }
    }
}
