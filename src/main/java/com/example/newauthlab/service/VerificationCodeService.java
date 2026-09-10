package com.example.newauthlab.service;

import jakarta.servlet.http.HttpSession;

import org.springframework.stereotype.Service;

@Service
public class VerificationCodeService {

    // セッションに保存する認証コードのキー
    private static final String CODE_KEY =
            "twoStageVerificationCode";

    // セッションに保存するメールアドレスのキー
    private static final String EMAIL_KEY =
            "twoStageVerificationEmail";


    // =========================
    // 認証コードを保存
    // =========================

    public void saveCode(
            HttpSession session,
            String email,
            String code) {

        session.setAttribute(CODE_KEY, code);
        session.setAttribute(EMAIL_KEY, email);
    }


    // =========================
    // 認証コードを取得
    // =========================

    public String getCode(
            HttpSession session) {

        Object code =
                session.getAttribute(CODE_KEY);

        if (code == null) {
            return null;
        }

        return code.toString();
    }


    // =========================
    // メールアドレスを取得
    // =========================

    public String getEmail(
            HttpSession session) {

        Object email =
                session.getAttribute(EMAIL_KEY);

        if (email == null) {
            return null;
        }

        return email.toString();
    }


    // =========================
    // 認証コードを確認
    // =========================

    public boolean verifyCode(
            HttpSession session,
            String inputCode) {

        String savedCode =
                getCode(session);

        if (savedCode == null) {
            return false;
        }

        return savedCode.equals(inputCode);
    }


    // =========================
    // 認証コードを削除
    // =========================

    public void clearCode(
            HttpSession session) {

        session.removeAttribute(CODE_KEY);
        session.removeAttribute(EMAIL_KEY);
    }
}
