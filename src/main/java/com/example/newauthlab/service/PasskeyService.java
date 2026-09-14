package com.example.newauthlab.service;

import java.util.List;
import java.util.Optional;

import org.springframework.stereotype.Service;

import com.example.newauthlab.entity.PasskeyCredential;
import com.example.newauthlab.entity.User;
import com.example.newauthlab.repository.PasskeyCredentialRepository;

@Service
public class PasskeyService {

    private final PasskeyCredentialRepository passkeyCredentialRepository;

    public PasskeyService(
            PasskeyCredentialRepository passkeyCredentialRepository) {
        this.passkeyCredentialRepository =
                passkeyCredentialRepository;
    }

    /**
     * Passkeyを登録する
     */
    public PasskeyCredential registerPasskey(
            User user,
            String credentialId,
            String publicKey,
            long signatureCount) {

        PasskeyCredential credential = new PasskeyCredential();

        credential.setCredentialId(credentialId);
        credential.setPublicKey(publicKey);
        credential.setSignatureCount(signatureCount);
        credential.setUser(user);

        return passkeyCredentialRepository.save(credential);
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
     * ユーザーのPasskey一覧を取得する
     */
    public List<PasskeyCredential> findByUser(User user) {

        return passkeyCredentialRepository
                .findByUser(user);
    }

    /**
     * 認証回数を更新する
     */
    public void updateSignatureCount(
            PasskeyCredential credential,
            long signatureCount) {

        credential.setSignatureCount(signatureCount);

        passkeyCredentialRepository.save(credential);
    }

    /**
     * Passkeyを削除する
     */
    public void deletePasskey(String credentialId) {

        passkeyCredentialRepository
                .deleteByCredentialId(credentialId);
    }
}