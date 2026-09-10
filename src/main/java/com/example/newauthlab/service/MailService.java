package com.example.newauthlab.service;

import java.util.Random;

import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class MailService {

    private final JavaMailSender mailSender;

    public MailService(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }


    // =========================
    // 認証コード生成
    // =========================

    public String generateCode() {

        Random random = new Random();

        int code = 100000 + random.nextInt(900000);

        return String.valueOf(code);
    }


    // =========================
    // 認証コード送信
    // =========================

    public void sendVerificationCode(
            String email,
            String code) {

        SimpleMailMessage message =
                new SimpleMailMessage();

        message.setTo(email);

        message.setSubject(
                "認証コードのお知らせ"
        );

        message.setText(
                "ログインに必要な認証コードをお知らせします。\n\n"
                + "認証コード："
                + code
                + "\n\n"
                + "このコードをログイン画面に入力してください。"
        );

        mailSender.send(message);
    }
}