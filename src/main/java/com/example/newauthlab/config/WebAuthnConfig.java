package com.example.newauthlab.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.web.webauthn.management.JdbcPublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.JdbcUserCredentialRepository;

@Configuration
public class WebAuthnConfig {

    @Bean
    public JdbcPublicKeyCredentialUserEntityRepository
            jdbcPublicKeyCredentialUserEntityRepository(
                    JdbcOperations jdbcOperations) {

        return new JdbcPublicKeyCredentialUserEntityRepository(
                jdbcOperations
        );
    }

    @Bean
    public JdbcUserCredentialRepository
            jdbcUserCredentialRepository(
                    JdbcOperations jdbcOperations) {

        return new JdbcUserCredentialRepository(
                jdbcOperations
        );
    }
}