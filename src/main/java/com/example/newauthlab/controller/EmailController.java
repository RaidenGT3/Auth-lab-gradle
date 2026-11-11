
package com.example.newauthlab.controller;

import java.util.Optional;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.example.newauthlab.entity.User;
import com.example.newauthlab.repository.UserRepository;
import com.example.newauthlab.service.AttackLoginTicketService;
import com.example.newauthlab.service.EmailService;
import com.example.newauthlab.service.MailService;
import com.example.newauthlab.service.VerificationCodeService;

@Controller
public class EmailController {

    private final EmailService emailService;

    private final UserRepository userRepository;

    private final AttackLoginTicketService attackLoginTicketService;

    private final VerificationCodeService verificationCodeService;

    private final MailService mailService;

    // =========================================================
    // コンストラクタ
    // =========================================================

    public EmailController(
            EmailService emailService,
            UserRepository userRepository,
            AttackLoginTicketService attackLoginTicketService,
            VerificationCodeService verificationCodeService,
            MailService mailService) {

        this.emailService = emailService;
        this.userRepository = userRepository;
        this.attackLoginTicketService = attackLoginTicketService;
        this.verificationCodeService = verificationCodeService;
        this.mailService = mailService;
    }

    // =========================================================
    // ユーザー名入力画面
    // =========================================================

    @GetMapping("/email")
    public String email() {

        return "email";
    }

    // =========================================================
    // OTP送信
    // =========================================================

    @PostMapping("/send-otp")
    public String sendOtp(
            @RequestParam("username") String username,
            @RequestParam(
                    value = "fromAttackSimulator",
                    required = false)
            String fromAttackSimulator,
            HttpSession session,
            Model model) {

        System.out.println("===== OTP発行開始 =====");
        System.out.println("Session ID = " + session.getId());
        System.out.println("Username = " + username);

        // =====================================================
        // usernameでユーザーを検索
        // =====================================================

        Optional<User> optionalUser =
                userRepository.findByUsername(username);

        if (optionalUser.isEmpty()) {

            model.addAttribute(
                    "error",
                    "ユーザーが見つかりません");

            return "email";
        }

        User user = optionalUser.get();

        // =====================================================
        // 登録メールアドレス取得
        // メール送信先としてのみ使用
        // =====================================================

        String email = user.getEmail();

        if (email == null || email.isBlank()) {

            model.addAttribute(
                    "error",
                    "登録されているメールアドレスがありません");

            return "email";
        }

        // =====================================================
        // OTP生成
        // =====================================================

        String otp = mailService.generateCode();

        // =====================================================
        // OTPと有効期限をセッションに保存
        // =====================================================

        verificationCodeService.saveCode(
                session,
                email,
                otp);

        // =====================================================
        // usernameをセッションに保存
        // =====================================================

        session.setAttribute(
                "emailOtpUsername",
                user.getUsername());

        // =====================================================
        // AttackSimulator経由か確認
        // =====================================================

        if ("true".equals(fromAttackSimulator)) {

            session.setAttribute(
                    "fromAttackSimulator",
                    true);

        } else {

            session.removeAttribute(
                    "fromAttackSimulator");
        }

        // =====================================================
        // メール送信
        // =====================================================

        emailService.sendOtp(
                email,
                otp);

        System.out.println("===== OTP送信完了 =====");
        System.out.println("Username = " + username);
        System.out.println("送信先Email = " + email);
        System.out.println("Session ID = " + session.getId());

        return "otp";
    }

    // =========================================================
    // OTP入力画面
    // =========================================================

    @GetMapping("/otp")
    public String otp() {

        return "otp";
    }

    // =========================================================
    // OTP確認
    // =========================================================

    @PostMapping("/verify-otp")
    public String verifyOtp(
            @RequestParam("otp") String otp,
            HttpSession session,
            HttpServletRequest request,
            HttpServletResponse response,
            Model model) {

        // =====================================================
        // OTP確認
        // =====================================================

        boolean verified =
                verificationCodeService.verifyCode(
                        session,
                        otp);

        if (!verified) {

            model.addAttribute(
                    "error",
                    "認証コードが正しくないか、有効期限が切れています");

            return "otp";
        }

        // =====================================================
        // username取得
        // =====================================================

        String username =
                (String) session.getAttribute(
                        "emailOtpUsername");

        if (username == null || username.isBlank()) {

            verificationCodeService.clearCode(session);

            model.addAttribute(
                    "error",
                    "ユーザー情報を確認できません");

            return "otp";
        }

        // =====================================================
        // usernameでユーザーを検索
        // =====================================================

        Optional<User> optionalUser =
                userRepository.findByUsername(username);

        if (optionalUser.isEmpty()) {

            verificationCodeService.clearCode(session);

            session.removeAttribute("emailOtpUsername");
            session.removeAttribute("email");

            model.addAttribute(
                    "error",
                    "ユーザーが見つかりません");

            return "otp";
        }

        User user = optionalUser.get();

        // =====================================================
        // AttackSimulator経由か確認
        // =====================================================

        boolean fromAttackSimulator =
                Boolean.TRUE.equals(
                        session.getAttribute(
                                "fromAttackSimulator"));

        // =====================================================
        // OTP削除
        // =====================================================

        verificationCodeService.clearCode(session);

        // =====================================================
        // AttackSimulator経由
        // =====================================================

        if (fromAttackSimulator) {

            String ticket =
                    attackLoginTicketService.createTicket(
                            user.getUsername());

            session.removeAttribute(
                    "fromAttackSimulator");

            session.removeAttribute(
                    "email");

            session.removeAttribute(
                    "emailOtpUsername");

            return "redirect:/attack-login?ticket="
                    + ticket;
        }

        // =====================================================
        // 通常のEmail OTPログイン
        // =====================================================

        loginSuccess(
                user,
                request,
                response);

        // =====================================================
        // セッション情報削除
        // =====================================================

        session.removeAttribute("email");
        session.removeAttribute("emailOtpUsername");
        session.removeAttribute("fromAttackSimulator");

        return "redirect:/home";
    }

    // =========================================================
    // 認証成功処理
    // =========================================================

    private void loginSuccess(
            User user,
            HttpServletRequest request,
            HttpServletResponse response) {

        org.springframework.security.core.Authentication authentication =
                new org.springframework.security.authentication
                        .UsernamePasswordAuthenticationToken(
                                user.getUsername(),
                                null,
                                java.util.List.of(
                                        new org.springframework.security
                                                .core.authority
                                                .SimpleGrantedAuthority(
                                                        "ROLE_USER")));

        org.springframework.security.core.context.SecurityContext securityContext =
                org.springframework.security.core.context
                        .SecurityContextHolder
                        .createEmptyContext();

        securityContext.setAuthentication(authentication);

        org.springframework.security.core.context
                .SecurityContextHolder
                .setContext(securityContext);

        org.springframework.security.web.context
                .HttpSessionSecurityContextRepository securityContextRepository =
                new org.springframework.security.web.context
                        .HttpSessionSecurityContextRepository();

        securityContextRepository.saveContext(
                securityContext,
                request,
                response);
    }

    // =========================================================
    // 認証成功画面
    // =========================================================

    @GetMapping("/success")
    public String success() {

        return "index";
    }
}
