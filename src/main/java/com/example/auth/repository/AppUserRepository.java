package com.example.auth.repository;

import com.example.auth.model.AppUser;
import com.example.auth.model.AuthProvider;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AppUserRepository extends JpaRepository<AppUser, Long> {
    Optional<AppUser> findByEmail(String email);
    Optional<AppUser> findByAuthProviderAndProviderId(AuthProvider authProvider, String providerId);
    Optional<AppUser> findByVerificationToken(String verificationToken);
    boolean existsByEmail(String email);
}
