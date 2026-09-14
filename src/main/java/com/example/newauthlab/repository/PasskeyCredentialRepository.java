package com.example.newauthlab.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.newauthlab.entity.PasskeyCredential;
import com.example.newauthlab.entity.User;

public interface PasskeyCredentialRepository
        extends JpaRepository<PasskeyCredential, Long> {

    /**
     * Credential IDからPasskeyを検索
     */
    Optional<PasskeyCredential> findByCredentialId(String credentialId);

    /**
     * ユーザーに登録されているPasskeyを取得
     */
    List<PasskeyCredential> findByUser(User user);

    /**
     * Credential IDからPasskeyを削除
     */
    void deleteByCredentialId(String credentialId);
}