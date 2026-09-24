package com.example.newauthlab.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.webauthn.management.MapPublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.MapUserCredentialRepository;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;

@Configuration
public class PasskeyConfig {

	/**
	 * WebAuthnのユーザー情報を管理するRepository
	 */
	@Bean
	public PublicKeyCredentialUserEntityRepository publicKeyCredentialUserEntityRepository() {
		return new MapPublicKeyCredentialUserEntityRepository();
	}

	/**
	 * WebAuthnのCredential情報を管理するRepository
	 */
	@Bean
	public UserCredentialRepository userCredentialRepository() {
		return new MapUserCredentialRepository();
	}
}
