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


    // =========================
    // 認証選択画面
    // =========================

    @GetMapping("/auth")
    public String authSelect() {
        return "auth-select";
    }


    // =========================
    // 認証選択処理
    // =========================

    @PostMapping("/auth/select")
    public String selectAuth(
            @RequestParam String authStage,
            @RequestParam String authFactor,
            Model model) {

        // 選択された認証段階
        model.addAttribute("authStage", authStage);

        // 選択された認証要素
        model.addAttribute("authFactor", authFactor);


        // 現時点では選択内容を確認するため、
        // ログイン画面へ移動する
        return "login";
    }


    // =========================
    // ログイン画面
    // =========================

    @GetMapping("/login")
    public String login() {
        return "login";
    }


    // =========================
    // ユーザー登録画面
    // =========================

    @GetMapping("/register")
    public String register() {
        return "register";
    }


    // =========================
    // ユーザー登録処理
    // =========================

    @PostMapping("/register")
    public String registerUser(
            @RequestParam String username,
            @RequestParam String password,
            Model model) {

        // ユーザー名がすでに存在するか確認
        if (userRepository.existsByUsername(username)) {

            model.addAttribute(
                    "error",
                    "そのユーザー名はすでに使用されています"
            );

            return "register";
        }


        // 新しいユーザーを作成
        User user = new User();

        user.setUsername(username);

        // パスワードをBCryptで暗号化
        user.setPassword(
                passwordEncoder.encode(password)
        );


        // データベースへ保存
        userRepository.save(user);


        // 登録後はログイン画面へ
        return "redirect:/login";
    }
}
