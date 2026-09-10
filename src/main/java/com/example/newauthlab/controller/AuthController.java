package com.example.newauthlab.controller;

import java.util.Optional;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.example.newauthlab.entity.User;
import com.example.newauthlab.repository.UserRepository;
import com.example.newauthlab.service.MailService;
import com.example.newauthlab.service.VerificationCodeService;

@Controller
public class AuthController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final MailService mailService;
    private final VerificationCodeService verificationCodeService;

    // Spring Securityのログイン状態をセッションに保存するために使用
    private final SecurityContextRepository securityContextRepository =
            new HttpSessionSecurityContextRepository();


    public AuthController(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            MailService mailService,
            VerificationCodeService verificationCodeService) {

        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.mailService = mailService;
        this.verificationCodeService = verificationCodeService;
    }


    // =========================
    // 認証選択画面
    // =========================

    @GetMapping("/auth")
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
    // 一段階認証
    // ユーザー名・パスワード確認
    // =========================

    @PostMapping("/login/one-stage")
    public String oneStageLoginProcess(
            @RequestParam String username,
            @RequestParam String password,
            HttpServletRequest request,
            HttpServletResponse response,
            Model model) {

        // =========================
        // ユーザーを検索
        // =========================

        Optional<User> optionalUser =
                userRepository.findByUsername(username);

        // ユーザーが存在しない場合
        if (optionalUser.isEmpty()) {

            model.addAttribute(
                    "error",
                    "ユーザー名またはパスワードが正しくありません"
            );

            return "login/one-stage";
        }


        // ユーザーを取得
        User user = optionalUser.get();


        // =========================
        // パスワードを確認
        // =========================

        if (!passwordEncoder.matches(
                password,
                user.getPassword())) {

            model.addAttribute(
                    "error",
                    "ユーザー名またはパスワードが正しくありません"
            );

            return "login/one-stage";
        }


        // =========================
        // Spring Securityにログイン情報を設定
        // =========================

        Authentication authentication =
                new UsernamePasswordAuthenticationToken(
                        user.getUsername(),
                        null,
                        java.util.Collections.emptyList()
                );


        SecurityContext context =
                SecurityContextHolder.createEmptyContext();

        context.setAuthentication(authentication);

        SecurityContextHolder.setContext(context);


        // =========================
        // ログイン状態をセッションに保存
        // =========================

        securityContextRepository.saveContext(
                context,
                request,
                response
        );


        // =========================
        // ログイン成功
        // =========================

        return "redirect:/";
    }


    // =========================
    // 二段階認証ログイン画面
    // =========================

    @GetMapping("/login/two-stage")
    public String twoStageLogin() {
        return "login/two-stage";
    }


    // =========================
    // 二段階認証
    // ユーザー名・パスワード確認
    // =========================

    @PostMapping("/login/two-stage")
    public String twoStageLoginProcess(
            @RequestParam String username,
            @RequestParam String password,
            HttpSession session,
            Model model) {

        // =========================
        // ユーザーを検索
        // =========================

        Optional<User> optionalUser =
                userRepository.findByUsername(username);

        // ユーザーが存在しない場合
        if (optionalUser.isEmpty()) {

            model.addAttribute(
                    "error",
                    "ユーザー名またはパスワードが正しくありません"
            );

            return "login/two-stage";
        }


        // ユーザーを取得
        User user = optionalUser.get();


        // =========================
        // パスワードを確認
        // =========================

        if (!passwordEncoder.matches(
                password,
                user.getPassword())) {

            model.addAttribute(
                    "error",
                    "ユーザー名またはパスワードが正しくありません"
            );

            return "login/two-stage";
        }


        // =========================
        // メールアドレスが登録されているか確認
        // =========================

        if (user.getEmail() == null ||
                user.getEmail().isBlank()) {

            model.addAttribute(
                    "error",
                    "メールアドレスが登録されていません"
            );

            return "login/two-stage";
        }


        // =========================
        // 認証コードを生成
        // =========================

        String code =
                mailService.generateCode();


        // =========================
        // 認証コードをセッションに保存
        // =========================

        verificationCodeService.saveCode(
                session,
                user.getEmail(),
                code
        );


        // =========================
        // 二段階認証で使用するユーザー名を保存
        // =========================

        session.setAttribute(
                "twoStageUsername",
                user.getUsername()
        );


        // =========================
        // 認証コードをメール送信
        // =========================

        mailService.sendVerificationCode(
                user.getEmail(),
                code
        );


        // =========================
        // 認証コード入力画面へ
        // =========================

        return "redirect:/login/two-stage/code";
    }


    // =========================
    // 二段階認証
    // 認証コード入力画面
    // =========================

    @GetMapping("/login/two-stage/code")
    public String twoStageCode(
            HttpSession session) {

        // 認証コードが存在しない場合は
        // 二段階認証の最初の画面へ戻す
        if (verificationCodeService.getCode(session) == null) {
            return "redirect:/login/two-stage";
        }

        return "login/two-stage-code";
    }


    // =========================
    // 二段階認証
    // 認証コード確認処理
    // =========================

    @PostMapping("/login/two-stage/code")
    public String verifyTwoStageCode(
            @RequestParam String code,
            HttpSession session,
            HttpServletRequest request,
            HttpServletResponse response,
            Model model) {

        // =========================
        // 認証コードが存在するか確認
        // =========================

        String savedCode =
                verificationCodeService.getCode(session);

        if (savedCode == null) {

            model.addAttribute(
                    "error",
                    "認証コードの有効期限が切れています。もう一度ログインしてください"
            );

            return "login/two-stage-code";
        }


        // =========================
        // 認証コードを確認
        // =========================

        if (!verificationCodeService.verifyCode(
                session,
                code)) {

            model.addAttribute(
                    "error",
                    "認証コードが正しくありません"
            );

            return "login/two-stage-code";
        }


        // =========================
        // ユーザー名をセッションから取得
        // =========================

        Object usernameObject =
                session.getAttribute("twoStageUsername");

        if (usernameObject == null) {

            model.addAttribute(
                    "error",
                    "認証情報が確認できません。もう一度ログインしてください"
            );

            verificationCodeService.clearCode(session);

            return "login/two-stage";
        }

        String username =
                usernameObject.toString();


        // =========================
        // ユーザーを取得
        // =========================

        Optional<User> optionalUser =
                userRepository.findByUsername(username);

        if (optionalUser.isEmpty()) {

            model.addAttribute(
                    "error",
                    "ユーザーが見つかりません"
            );

            verificationCodeService.clearCode(session);

            return "login/two-stage";
        }

        User user = optionalUser.get();


        // =========================
        // Spring Securityにログイン情報を設定
        // =========================

        Authentication authentication =
                new UsernamePasswordAuthenticationToken(
                        user.getUsername(),
                        null,
                        java.util.Collections.emptyList()
                );


        SecurityContext context =
                SecurityContextHolder.createEmptyContext();

        context.setAuthentication(authentication);

        SecurityContextHolder.setContext(context);


        // =========================
        // ログイン状態をセッションに保存
        // =========================

        securityContextRepository.saveContext(
                context,
                request,
                response
        );


        // =========================
        // 使用済み認証コードを削除
        // =========================

        verificationCodeService.clearCode(session);


        // =========================
        // 二段階認証用のユーザー名も削除
        // =========================

        session.removeAttribute("twoStageUsername");


        // =========================
        // ログイン成功
        // =========================

        return "redirect:/";
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
        return "redirect:/auth";
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
            @RequestParam String email,
            Model model) {

        // =========================
        // ユーザー名がすでに存在するか確認
        // =========================

        if (userRepository.existsByUsername(username)) {

            model.addAttribute(
                    "error",
                    "そのユーザー名はすでに使用されています"
            );

            return "register";
        }


        // =========================
        // 新しいユーザーを作成
        // =========================

        User user = new User();

        user.setUsername(username);


        // パスワードをBCryptで暗号化
        user.setPassword(
                passwordEncoder.encode(password)
        );


        // メールアドレスを保存
        user.setEmail(email);


        // データベースへ保存
        userRepository.save(user);


        // =========================
        // 登録後はログイン画面へ
        // =========================

        return "redirect:/login";
    }
}