package com.example.auth.controller;

import com.example.auth.AuthApplication;
import com.example.auth.dto.SignupRequest;
import com.example.auth.repository.AppUserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(
    classes = AuthApplication.class,
    properties = {
        "spring.autoconfigure.exclude=org.springframework.boot.actuate.autoconfigure.mail.MailHealthContributorAutoConfiguration",
        "spring.mail.host=localhost"
    }
)
@AutoConfigureMockMvc
@ActiveProfiles("dev")
@Transactional
public class AuthIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AppUserRepository userRepository;

    @Autowired
    private ObjectMapper objectMapper;

    /**
     * Mock JavaMailSender to prevent SMTP connection errors in tests.
     * The EmailService logs emails to console when mailSender is null,
     * but having a mock allows the bean to be injected without SMTP config.
     */
    @MockBean
    private JavaMailSender javaMailSender;

    @BeforeEach
    void setUp() {
        userRepository.deleteAll();
    }

    @Test
    void testLocalSignupFlow_Success() throws Exception {
        SignupRequest signupRequest = SignupRequest.builder()
            .email("integration@example.com")
            .displayName("Integration Tester")
            .password("SecurePass123!") // fits policy: min 8, 1 upper, 1 lower, 1 digit
            .build();

        mockMvc.perform(post("/api/auth/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(signupRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message", containsString("Registration successful")))
                .andExpect(jsonPath("$.email").value("integration@example.com"));

        // Verify record in database
        assertTrue(userRepository.existsByEmail("integration@example.com"));
    }

    @Test
    void testLocalSignupFlow_ValidationFailure() throws Exception {
        SignupRequest invalidRequest = SignupRequest.builder()
            .email("bad-email")
            .displayName("")
            .password("simple") // breaks policy rules
            .build();

        mockMvc.perform(post("/api/auth/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest());
    }
}
