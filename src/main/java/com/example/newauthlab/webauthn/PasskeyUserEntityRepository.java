package com.example.newauthlab.webauthn;

import org.springframework.stereotype.Component;

import com.example.newauthlab.entity.User;
import com.example.newauthlab.repository.UserRepository;

@Component
public class PasskeyUserEntityRepository {

    private final UserRepository userRepository;

    public PasskeyUserEntityRepository(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * usernameからユーザーを取得
     */
    public User findUser(String username) {
        return userRepository.findByUsername(username)
                .orElse(null);
    }
}