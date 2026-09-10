package com.example.newauthlab.controller;

import java.util.Random;

import jakarta.servlet.http.HttpSession;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.example.newauthlab.service.EmailService;

@Controller
public class EmailController {

    private final EmailService emailService;

    public EmailController(EmailService emailService) {
        this.emailService = emailService;
    }

    // メールアドレス入力画面
    @GetMapping("/email")
    public String email() {
        return "email";
    }

    // OTPを送信
    @PostMapping("/send-otp")
    public String sendOtp(
            @RequestParam("email") String email,
            HttpSession session) {

        // 6桁のランダムなOTPを作成
        String otp = String.format(
                "%06d",
                new Random().nextInt(1000000)
        );

        // OTPをセッションに保存
        session.setAttribute("otp", otp);

        // メールアドレスもセッションに保存
        session.setAttribute("email", email);

        // メール送信
        emailService.sendOtp(email, otp);

        // OTP入力画面へ
        return "otp";
    }

    // OTP入力画面
    @GetMapping("/otp")
    public String otp() {
        return "otp";
    }

    // OTPを確認
    @PostMapping("/verify-otp")
    public String verifyOtp(
            @RequestParam("otp") String otp,
            HttpSession session) {

        // セッションに保存しているOTPを取得
        String savedOtp = (String) session.getAttribute("otp");

        // 入力されたOTPと保存されているOTPを比較
        if (savedOtp != null && savedOtp.equals(otp)) {

            // 認証成功
            session.removeAttribute("otp");

            return "emialSuccess";
        }

        // 認証失敗
        return "otp";
    }

    // 認証成功画面
    @GetMapping("/success")
    public String success() {
        return "emialSuccess";
    }
}