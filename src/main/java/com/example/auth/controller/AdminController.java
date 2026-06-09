package com.example.auth.controller;

import com.example.auth.model.AppUser;
import com.example.auth.model.Role;
import com.example.auth.repository.AppUserRepository;
import com.example.auth.repository.RoleRepository;
import com.example.auth.service.AuditService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
@Slf4j
@PreAuthorize("hasRole('ADMIN')")
@Tag(name = "Admin Management APIs", description = "Admin-only endpoints for user account administration")
public class AdminController {

    private final AppUserRepository userRepository;
    private final RoleRepository roleRepository;
    private final AuditService auditService;

    @GetMapping("/users")
    @Operation(summary = "List all user accounts", description = "Returns a complete list of registered users in the database.")
    @ApiResponse(responseCode = "200", description = "List of users retrieved successfully")
    public ResponseEntity<List<AppUser>> getAllUsers() {
        log.info("Admin list users requested");
        List<AppUser> users = userRepository.findAll();
        // Hide password hashes for safety in output
        users.forEach(u -> u.setPasswordHash("[PROTECTED]"));
        return ResponseEntity.ok(users);
    }

    @PutMapping("/users/{id}/status")
    @Operation(summary = "Toggle user account active status", description = "Enables or disables a user account.")
    @ApiResponse(responseCode = "200", description = "Status updated successfully")
    public ResponseEntity<Map<String, String>> toggleUserStatus(@PathVariable Long id, @RequestParam boolean enabled, Authentication authentication) {
        log.info("Admin status toggle requested for user ID: {} to enabled: {}", id, enabled);
        AppUser user = userRepository.findById(id)
            .orElseThrow(() -> new IllegalArgumentException("User with ID " + id + " not found."));

        user.setEnabled(enabled);
        userRepository.save(user);
        auditService.record("ADMIN", actor(authentication), "USER_STATUS", "USER", user.getEmail(), enabled ? "ENABLED" : "DISABLED");

        return ResponseEntity.ok(Map.of("message", "User account status updated successfully to " + (enabled ? "ENABLED" : "DISABLED")));
    }

    @PutMapping("/users/{id}/roles")
    @Operation(summary = "Assign or alter user roles", description = "Assigns non-admin roles to a user account.")
    @Transactional
    public ResponseEntity<Map<String, String>> assignUserRole(@PathVariable Long id, @RequestParam String roleName, Authentication authentication) {
        log.info("Admin role assignment requested for user ID: {} to role: {}", id, roleName);
        String normalizedRoleName = roleName.toUpperCase();
        if ("ADMIN".equals(normalizedRoleName)) {
            throw new IllegalArgumentException("ADMIN role cannot be assigned through this endpoint. Only the configured bootstrap admin can have ADMIN access.");
        }

        AppUser user = userRepository.findById(id)
            .orElseThrow(() -> new IllegalArgumentException("User with ID " + id + " not found."));

        Role role = roleRepository.findByName(normalizedRoleName)
            .orElseThrow(() -> new IllegalArgumentException("Role " + roleName + " not found."));

        user.setRoles(new HashSet<>(Collections.singleton(role)));
        userRepository.save(user);
        auditService.record("ADMIN", actor(authentication), "ROLE_ASSIGNMENT", "USER_ROLE", user.getEmail() + ":" + role.getName(), "SUCCESS");

        return ResponseEntity.ok(Map.of("message", "User role successfully assigned to " + role.getName()));
    }

    private static String actor(Authentication authentication) {
        return authentication != null ? authentication.getName() : null;
    }
}
