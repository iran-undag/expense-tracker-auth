package com.example.auth.controller;

import com.example.auth.dto.SignupRequest;
import com.example.auth.service.AuthService;
import com.example.auth.service.UserPrincipal;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@RequiredArgsConstructor
@Slf4j
public class AuthPageController {

    private final AuthService authService;

    @Value("${app.frontend.base-url:http://localhost:5173}")
    private String frontendBaseUrl;

    @GetMapping("/")
    public String home(Authentication authentication, Model model) {
        if (authentication != null && authentication.isAuthenticated()) {
            model.addAttribute("authenticated", true);
            model.addAttribute("username", authentication.getName());
        } else {
            model.addAttribute("authenticated", false);
        }
        model.addAttribute("frontendBaseUrl", frontendBaseUrl);
        return "index";
    }

    @GetMapping("/favicon.ico")
    public ResponseEntity<Void> favicon() {
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/login")
    public String loginPage(@RequestParam(value = "error", required = false) String error, 
                            @RequestParam(value = "logout", required = false) String logout, 
                            Model model) {
        if (error != null) {
            model.addAttribute("errorMessage", "Invalid email or password / Unverified account.");
        }
        if (logout != null) {
            model.addAttribute("successMessage", "You have been logged out successfully.");
        }
        return "login";
    }

    @GetMapping("/signup")
    public String signupPage(Model model) {
        model.addAttribute("signupRequest", new SignupRequest());
        return "signup";
    }

    @PostMapping("/signup")
    public String signupSubmit(@Valid @ModelAttribute("signupRequest") SignupRequest request, 
                               BindingResult bindingResult, 
                               Model model) {
        log.info("Form submission: signup for: {}", request.getEmail());
        if (bindingResult.hasErrors()) {
            return "signup";
        }

        try {
            authService.registerLocalUser(request);
            model.addAttribute("successMessage", "Registration successful! A verification email has been logged to the console. Please verify to activate your account.");
            return "login";
        } catch (Exception e) {
            model.addAttribute("errorMessage", e.getMessage());
            return "signup";
        }
    }

    @GetMapping("/verify-email")
    public String verifyEmail(@RequestParam("token") String token, Model model) {
        log.info("Received web click verification for token");
        try {
            authService.verifyEmail(token);
            model.addAttribute("verified", true);
            model.addAttribute("message", "Your email has been verified successfully. You can now log in!");
            model.addAttribute("frontendBaseUrl", frontendBaseUrl);
        } catch (Exception e) {
            model.addAttribute("verified", false);
            model.addAttribute("message", "Email verification failed: " + e.getMessage());
            model.addAttribute("frontendBaseUrl", frontendBaseUrl);
        }
        return "verify-email";
    }
}
