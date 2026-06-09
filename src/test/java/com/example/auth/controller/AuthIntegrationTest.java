package com.example.auth.controller;

import com.example.auth.config.CorrelationId;
import com.example.auth.AuthApplication;
import com.example.auth.dto.SignupRequest;
import com.example.auth.model.AppUser;
import com.example.auth.model.AuthProvider;
import com.example.auth.model.Role;
import com.example.auth.repository.AppUserRepository;
import com.example.auth.repository.RoleRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import java.net.URI;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;

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
    private RoleRepository roleRepository;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

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

    @Test
    void testVerifyEmail_ExpiredTokenReturnsBadRequest() throws Exception {
        SignupRequest signupRequest = SignupRequest.builder()
            .email("expired@example.com")
            .displayName("Expired Tester")
            .password("SecurePass123!")
            .build();

        mockMvc.perform(post("/api/auth/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(signupRequest)))
            .andExpect(status().isOk());

        AppUser user = userRepository.findByEmail("expired@example.com").orElseThrow();
        String token = user.getVerificationToken();
        user.setVerificationTokenCreatedAt(LocalDateTime.now().minusDays(31));
        userRepository.flush();

        mockMvc.perform(get("/api/auth/verify-email").param("token", token))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.error").value("Token Expired"));
    }

    @Test
    void testAdminAssignRole_RejectsAdminRole() throws Exception {
        AppUser targetUser = createUser("target@example.com", "USER");

        mockMvc.perform(put("/api/admin/users/{id}/roles", targetUser.getId())
                .param("roleName", "ADMIN")
                .with(user("admin@example.com").roles("ADMIN"))
                .with(csrf()))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.message", containsString("ADMIN role cannot be assigned")));
    }

    @Test
    void testAdminAssignRole_AllowsUserRole() throws Exception {
        AppUser targetUser = createUser("target@example.com", "USER");

        mockMvc.perform(put("/api/admin/users/{id}/roles", targetUser.getId())
                .param("roleName", "USER")
                .with(user("admin@example.com").roles("ADMIN"))
                .with(csrf()))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.message", containsString("USER")));
    }

    @Test
    void requestWithCorrelationId_shouldEchoHeader() throws Exception {
        mockMvc.perform(get("/api/auth/verify-email")
                .param("token", "missing-token")
                .header(CorrelationId.HEADER_NAME, "auth-correlation-id"))
            .andExpect(status().isBadRequest())
            .andExpect(header().string(CorrelationId.HEADER_NAME, "auth-correlation-id"));
    }

    @Test
    void requestWithoutCorrelationId_shouldGenerateHeader() throws Exception {
        mockMvc.perform(get("/api/auth/verify-email")
                .param("token", "missing-token"))
            .andExpect(status().isBadRequest())
            .andExpect(header().exists(CorrelationId.HEADER_NAME));
    }

    @Test
    void corsPreflight_shouldAllowCorrelationIdHeader() throws Exception {
        mockMvc.perform(options("/actuator/health")
                .header("Origin", "http://localhost:5173")
                .header("Access-Control-Request-Method", "GET")
                .header("Access-Control-Request-Headers", CorrelationId.HEADER_NAME))
            .andExpect(status().isOk())
            .andExpect(header().string("Access-Control-Allow-Headers", containsString(CorrelationId.HEADER_NAME)));
    }

    @Test
    void loginFormPostWithNullOrigin_shouldNotBeRejectedByCors() throws Exception {
        mockMvc.perform(post("/login")
                .header("Origin", "null")
                .param("email", "missing@example.com")
                .param("password", "SecurePass123!")
                .with(csrf()))
            .andExpect(status().is3xxRedirection())
            .andExpect(header().string("Location", containsString("/login?error=invalid")));
    }

    @Test
    void directSuccessfulLogin_shouldRedirectToHome() throws Exception {
        createUser("direct-login@example.com", "USER", "SecurePass123!");

        mockMvc.perform(post("/login")
                .param("email", "direct-login@example.com")
                .param("password", "SecurePass123!")
                .with(csrf()))
            .andExpect(status().is3xxRedirection())
            .andExpect(redirectedUrl("/"));
    }

    @Test
    void authenticatedHomePage_shouldRenderPostLogoutForm() throws Exception {
        mockMvc.perform(get("/")
                .with(user("home-user@example.com").roles("USER")))
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("method=\"post\"")))
            .andExpect(content().string(containsString("action=\"/logout\"")))
            .andExpect(content().string(containsString("Sign Out")));
    }

    @Test
    void postLogoutWithCsrf_shouldRedirectToLoginLogoutPage() throws Exception {
        mockMvc.perform(post("/logout")
                .with(user("logout-user@example.com").roles("USER"))
                .with(csrf()))
            .andExpect(status().is3xxRedirection())
            .andExpect(redirectedUrl("/login?logout"));
    }

    @Test
    void getLogout_shouldNotPerformLogout() throws Exception {
        mockMvc.perform(get("/logout")
                .with(user("logout-user@example.com").roles("USER")))
            .andExpect(status().isNotFound());
    }

    @Test
    void successfulLoginAfterProtectedRequest_shouldResumeSavedRequest() throws Exception {
        createUser("saved-request@example.com", "USER", "SecurePass123!");

        MvcResult protectedRequest = mockMvc.perform(get("/api/auth/me")
                .accept(MediaType.TEXT_HTML))
            .andExpect(status().is3xxRedirection())
            .andExpect(header().string("Location", containsString("/login")))
            .andReturn();
        MockHttpSession session = (MockHttpSession) protectedRequest.getRequest().getSession(false);

        mockMvc.perform(post("/login")
                .session(session)
                .param("email", "saved-request@example.com")
                .param("password", "SecurePass123!")
                .with(csrf()))
            .andExpect(status().is3xxRedirection())
            .andExpect(header().string("Location", containsString("/api/auth/me")));
    }

    @Test
    void signupFormPostWithNullOrigin_shouldNotBeRejectedByCors() throws Exception {
        mockMvc.perform(post("/signup")
                .header("Origin", "null")
                .param("email", "loopback@example.com")
                .param("displayName", "Loopback User")
                .param("password", "SecurePass123!")
                .with(csrf()))
            .andExpect(status().isOk());
    }

    @Test
    void faviconRequest_shouldNotBeHandledAsServerError() throws Exception {
        mockMvc.perform(get("/favicon.ico"))
            .andExpect(status().isNoContent());
    }

    @Test
    void errorEndpoint_shouldNotRedirectToLogin() throws Exception {
        mockMvc.perform(get("/error"))
            .andExpect(header().doesNotExist("Location"));
    }

    @Test
    void devOAuthClient_shouldBeRegisteredInJdbcRepository() {
        RegisteredClient registeredClient = registeredClientRepository.findByClientId("expense-tracker-web");
        assertNotNull(registeredClient);
        assertTrue(registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE));
        assertTrue(registeredClient.getRedirectUris().contains("https://oauth.pstmn.io/v1/callback"));
    }

    @Test
    void postmanAuthorizeRequest_shouldRedirectUnauthenticatedUserToLogin() throws Exception {
        mockMvc.perform(get(URI.create("http://localhost/oauth2/authorize?response_type=code"
                + "&client_id=expense-tracker-web"
                + "&scope=openid%20profile"
                + "&redirect_uri=https%3A%2F%2Foauth.pstmn.io%2Fv1%2Fcallback"
                + "&code_challenge=J_nGoNrw_tXCCZPgYMl3G3uZ2ocC49Iz9_5P_lFfcrU"
                + "&code_challenge_method=S256")))
            .andExpect(status().is3xxRedirection())
            .andExpect(header().string("Location", containsString("/login")));
    }

    private AppUser createUser(String email, String roleName) {
        return createUser(email, roleName, null);
    }

    private AppUser createUser(String email, String roleName, String rawPassword) {
        Role role = roleRepository.findByName(roleName)
            .orElseGet(() -> roleRepository.save(Role.builder().name(roleName).build()));
        AppUser user = AppUser.builder()
            .email(email)
            .passwordHash(rawPassword == null ? "encoded" : passwordEncoder.encode(rawPassword))
            .displayName(email)
            .enabled(true)
            .emailVerified(true)
            .authProvider(AuthProvider.LOCAL)
            .roles(new HashSet<>(Set.of(role)))
            .build();
        return userRepository.saveAndFlush(user);
    }
}
