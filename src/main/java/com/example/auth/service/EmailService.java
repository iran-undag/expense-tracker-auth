package com.example.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailService {

    @Autowired(required = false)
    private JavaMailSender mailSender;

    @Value("${spring.mail.host:localhost}")
    private String mailHost;

    @Value("${app.auth.verification-base-url:http://localhost:9000/verify-email}")
    private String verificationBaseUrl;

    public void sendVerificationEmail(String email, String token) {
        String verificationUrl = verificationBaseUrl + "?token=" + token;
        
        // Log to console in ALL modes for extremely easy visibility and automated testing
        log.info("----------------------------------------------------------------");
        log.info("REGISTRATION VERIFICATION EMAIL FOR: {}", email);
        log.info("Click the link to verify your email and activate your account:");
        log.info("URL: {}", verificationUrl);
        log.info("----------------------------------------------------------------");

        // Send real email if we're not using dummy localhost mailHost and mailSender is present
        if (mailSender != null && !mailHost.equals("localhost")) {
            try {
                SimpleMailMessage message = new SimpleMailMessage();
                message.setTo(email);
                message.setSubject("Expense Tracker - Verify your Email Address");
                message.setText("Welcome to Expense Tracker! Please verify your email by clicking the link:\n" + verificationUrl);
                mailSender.send(message);
                log.info("Real verification email sent to {}", email);
            } catch (Exception e) {
                log.error("Failed to send real verification email to {}", email, e);
            }
        }
    }
}
