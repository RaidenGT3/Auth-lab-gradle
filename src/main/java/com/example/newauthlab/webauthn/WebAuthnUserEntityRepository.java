package com.example.newauthlab.webauthn;

import org.springframework.stereotype.Component;

import com.example.newauthlab.entity.User;
import com.example.newauthlab.repository.UserRepository;

@Component
public class WebAuthnUserEntityRepository {

    private final UserRepository userRepository;

    public WebAuthnUserEntityRepository(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * usernameからWebAuthn登録対象のユーザーを取得する
     */
    public User findByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElse(null);
    }

    /**
     * WebAuthnで使用するユーザーID
     *
     * UserテーブルのLong型IDを
     * WebAuthn用のbyte配列に変換する。
     */
    public byte[] getUserId(User user) {
        if (user == null || user.getId() == null) {
            return null;
        }

        return String.valueOf(user.getId())
                .getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }
}