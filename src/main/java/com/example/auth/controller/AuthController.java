package com.example.auth.controller;

import com.example.auth.dto.SignupRequest;
import com.example.auth.dto.UserProfile;
import com.example.auth.model.AppUser;
import com.example.auth.service.AuthService;
import com.example.auth.service.UserPrincipal;
import com.example.auth.service.CustomOidcUserPrincipal;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Authentication REST APIs", description = "Endpoints for local user signup, verification email triggers, and session queries")
public class AuthController {

    private final AuthService authService;

    @PostMapping("/signup")
    @Operation(summary = "Register a local user account", description = "Creates a new user record in inactive status and logs/sends a verification email.")
    @ApiResponse(responseCode = "200", description = "User registered successfully, verification email triggered")
    @ApiResponse(responseCode = "409", description = "Email is already occupied")
    public ResponseEntity<Map<String, String>> registerUser(@Valid @RequestBody SignupRequest request) {
        log.info("Received REST local signup request for: {}", request.getEmail());
        AppUser user = authService.registerLocalUser(request);
        return ResponseEntity.ok(Map.of(
            "message", "Registration successful. A verification email has been sent to " + user.getEmail(),
            "email", user.getEmail()
        ));
    }

    @GetMapping("/verify-email")
    @Operation(summary = "Verify account email address", description = "Activates the user account associated with the verification token.")
    @ApiResponse(responseCode = "200", description = "Email verified and account activated successfully")
    @ApiResponse(responseCode = "400", description = "Invalid or expired token")
    public ResponseEntity<Map<String, String>> verifyEmail(@RequestParam("token") String token) {
        log.info("Received REST verification request for token");
        authService.verifyEmail(token);
        return ResponseEntity.ok(Map.of(
            "message", "Email verified and account activated successfully. You can now log in."
        ));
    }

    @PostMapping("/resend-verification")
    @Operation(summary = "Resend account verification email", description = "Generates a new token and triggers verification email.")
    @ApiResponse(responseCode = "200", description = "Verification email resent successfully")
    public ResponseEntity<Map<String, String>> resendVerification(@RequestParam("email") String email) {
        log.info("Received request to resend verification email for {}", email);
        authService.resendVerificationEmail(email);
        return ResponseEntity.ok(Map.of(
            "message", "Verification email sent successfully."
        ));
    }

    @GetMapping("/me")
    @Operation(summary = "Get current user profile", description = "Returns active session user details.")
    @ApiResponse(responseCode = "200", description = "User profile resolved")
    @ApiResponse(responseCode = "401", description = "Unauthorized")
    public ResponseEntity<UserProfile> getCurrentUser(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(401).build();
        }

        Object principal = authentication.getPrincipal();
        UserProfile.UserProfileBuilder builder = UserProfile.builder();

        if (principal instanceof UserPrincipal userPrincipal) {
            AppUser user = userPrincipal.getUser();
            builder.id(user.getId())
                .email(user.getEmail())
                .displayName(user.getDisplayName())
                .authProvider(user.getAuthProvider().name())
                .roles(userPrincipal.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toSet()));
        } else if (principal instanceof CustomOidcUserPrincipal oidcPrincipal) {
            AppUser user = oidcPrincipal.getUser();
            builder.id(user.getId())
                .email(user.getEmail())
                .displayName(user.getDisplayName())
                .authProvider(user.getAuthProvider().name())
                .roles(oidcPrincipal.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toSet()));
        } else {
            return ResponseEntity.status(401).build();
        }

        return ResponseEntity.ok(builder.build());
    }
}
