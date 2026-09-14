package com.example.newauthlab.webauthn;

import java.util.List;
import java.util.Optional;

import org.springframework.stereotype.Component;

import com.example.newauthlab.entity.PasskeyCredential;
import com.example.newauthlab.entity.User;
import com.example.newauthlab.repository.PasskeyCredentialRepository;

@Component
public class WebAuthnCredentialRepository {

    private final PasskeyCredentialRepository passkeyCredentialRepository;

    public WebAuthnCredentialRepository(
            PasskeyCredentialRepository passkeyCredentialRepository) {
        this.passkeyCredentialRepository = passkeyCredentialRepository;
    }

    /**
     * Credential IDからPasskeyを取得する
     */
    public Optional<PasskeyCredential> findByCredentialId(
            String credentialId) {

        return passkeyCredentialRepository
                .findByCredentialId(credentialId);
    }

    /**
     * ユーザーに登録されているPasskeyを取得する
     */
    public List<PasskeyCredential> findByUser(User user) {

        return passkeyCredentialRepository
                .findByUser(user);
    }

    /**
     * Passkeyを保存する
     */
    public PasskeyCredential save(PasskeyCredential credential) {

        return passkeyCredentialRepository.save(credential);
    }

    /**
     * Passkeyを削除する
     */
    public void deleteByCredentialId(String credentialId) {

        passkeyCredentialRepository
                .deleteByCredentialId(credentialId);
    }
}