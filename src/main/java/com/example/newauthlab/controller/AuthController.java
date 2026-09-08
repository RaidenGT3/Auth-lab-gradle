package com.example.newauthlab.controller;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.example.newauthlab.entity.User;
import com.example.newauthlab.repository.UserRepository;

@Controller
public class AuthController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public AuthController(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder) {

        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    // ログイン画面
    @GetMapping("/login")
    public String login() {
        return "login";
    }

    // ユーザー登録画面
    @GetMapping("/register")
    public String register() {
        return "register";
    }

    // ユーザー登録処理
    @PostMapping("/register")
    public String registerUser(
            @RequestParam String username,
            @RequestParam String password,
            Model model) {

        if (userRepository.existsByUsername(username)) {
            model.addAttribute("error", "そのユーザー名はすでに使用されています");
            return "register";
        }

        User user = new User();

        user.setUsername(username);

        // パスワードをBCryptで暗号化
        user.setPassword(passwordEncoder.encode(password));

        userRepository.save(user);

        return "redirect:/login";
    }
}