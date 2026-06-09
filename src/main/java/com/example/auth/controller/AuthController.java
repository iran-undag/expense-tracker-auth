package com.example.auth.controller;

import com.example.auth.dto.SignupRequest;
import com.example.auth.dto.UserProfile;
import com.example.auth.model.AppUser;
import com.example.auth.service.AuditService;
import com.example.auth.service.AuthService;
import com.example.auth.service.UserPrincipal;
import com.example.auth.service.CustomOidcUserPrincipal;
import com.example.auth.service.TokenBlacklistService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.web.bind.annotation.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Authentication REST APIs", description = "Endpoints for local user signup, verification email triggers, and session queries")
public class AuthController {

    private final AuthService authService;
    private final TokenBlacklistService tokenBlacklistService;
    private final JwtDecoder jwtDecoder;
    private final AuditService auditService;

    @PostMapping("/signup")
    @Operation(summary = "Register a local user account", description = "Creates a new user record in inactive status and logs/sends a verification email.")
    @ApiResponse(responseCode = "200", description = "User registered successfully, verification email triggered")
    @ApiResponse(responseCode = "409", description = "Email is already occupied")
    public ResponseEntity<Map<String, String>> registerUser(@Valid @RequestBody SignupRequest request) {
        log.info("Received REST local signup request for: {}", request.getEmail());
        AppUser user = authService.registerLocalUser(request);
        auditService.record("AUTHENTICATION", user.getEmail(), "SIGNUP", "SUCCESS");
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
        try {
            authService.verifyEmail(token);
            auditService.record("EMAIL_VERIFICATION", null, "VERIFY_EMAIL", "SUCCESS");
        } catch (RuntimeException ex) {
            auditService.record("EMAIL_VERIFICATION", null, "VERIFY_EMAIL", "FAILURE");
            throw ex;
        }
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
        auditService.record("EMAIL_VERIFICATION", email, "RESEND_VERIFICATION", "SUCCESS");
        return ResponseEntity.ok(Map.of(
            "message", "Verification email sent successfully."
        ));
    }

    @PostMapping("/logout")
    @Operation(summary = "Logout and revoke bearer token", description = "Revokes the bearer token presented on this request.")
    @ApiResponse(responseCode = "200", description = "Logout processed")
    public ResponseEntity<Map<String, String>> logout(HttpServletRequest request) {
        String token = bearerToken(request);
        if (token != null) {
            tokenBlacklistService.blacklistToken(token, remainingTtl(token));
        }
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
        auditService.record("AUTHENTICATION", null, "LOGOUT", "SUCCESS");
        return ResponseEntity.ok(Map.of("message", "Logged out successfully."));
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
        } else if (principal instanceof Jwt jwt) {
            Number userId = jwt.getClaim("userId");
            builder.id(userId != null ? userId.longValue() : null)
                .email(jwt.getClaimAsString("email"))
                .displayName(jwt.getSubject())
                .authProvider("JWT")
                .roles(authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toSet()));
        } else {
            return ResponseEntity.status(401).build();
        }

        return ResponseEntity.ok(builder.build());
    }

    private Duration remainingTtl(String token) {
        try {
            Jwt jwt = jwtDecoder.decode(token);
            Instant expiresAt = jwt.getExpiresAt();
            if (expiresAt == null) {
                return Duration.ofHours(1);
            }
            return Duration.between(Instant.now(), expiresAt);
        } catch (Exception ex) {
            return Duration.ofHours(1);
        }
    }

    private static String bearerToken(HttpServletRequest request) {
        String authorization = request.getHeader("Authorization");
        if (authorization != null && authorization.startsWith("Bearer ")) {
            return authorization.substring(7);
        }
        return null;
    }
}
