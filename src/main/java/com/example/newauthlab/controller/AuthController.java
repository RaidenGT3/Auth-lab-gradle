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

    @GetMapping({"/","/auth"})
    public String authSelect() {
        return "auth-select";
    }


    // =========================
    // 認証方式選択処理
    // =========================

    @PostMapping("/auth/select")
    public String selectAuth(
            @RequestParam String authType) {

        switch (authType) {

            // 一段階認証
            case "one-stage":
                return "redirect:/login/one-stage";


            // 二段階認証
            case "two-stage":
                return "redirect:/login/two-stage";


            // 三段階認証
            case "three-stage":
                return "redirect:/login/three-stage";


            // 一要素認証
            case "one-factor":
                return "redirect:/login/one-factor";


            // 二要素認証
            case "two-factor":
                return "redirect:/login/two-factor";


            // 三要素認証
            case "three-factor":
                return "redirect:/login/three-factor";


            // 想定外の値が送られた場合
            default:
                return "redirect:/auth";
        }
    }


    // =========================
    // 一段階認証ログイン画面
    // =========================

    @GetMapping("/login/one-stage")
    public String oneStageLogin() {
        return "login/one-stage";
    }


    // =========================
    // 二段階認証ログイン画面
    // =========================

    @GetMapping("/login/two-stage")
    public String twoStageLogin() {
        return "login/two-stage";
    }


    // =========================
    // 三段階認証ログイン画面
    // =========================

    @GetMapping("/login/three-stage")
    public String threeStageLogin() {
        return "login/three-stage";
    }


    // =========================
    // 一要素認証ログイン画面
    // =========================

    @GetMapping("/login/one-factor")
    public String oneFactorLogin() {
        return "login/one-factor";
    }


    // =========================
    // 二要素認証ログイン画面
    // =========================

    @GetMapping("/login/two-factor")
    public String twoFactorLogin() {
        return "login/two-factor";
    }


    // =========================
    // 三要素認証ログイン画面
    // =========================

    @GetMapping("/login/three-factor")
    public String threeFactorLogin() {
        return "login/three-factor";
    }


    // =========================
    // 通常ログイン画面
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