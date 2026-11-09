
package com.example.newauthlab.service;

import java.time.LocalDateTime;

import jakarta.servlet.http.HttpSession;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

@Service
public class VerificationCodeService {

    // セッションに保存する認証コードのキー
    private static final String CODE_KEY =
            "twoStageVerificationCode";

    // メールアドレスのキー
    private static final String EMAIL_KEY =
            "twoStageVerificationEmail";

    // 有効期限のキー
    private static final String EXPIRES_AT_KEY =
            "twoStageVerificationExpiresAt";

    // OTPの有効期限（分）
    public int timeout = 5;

    // OTP有効期限を取得
    public int getTimeout() {
        return timeout;
    }

    // =====================================================
    // 認証コードを保存
    // =====================================================

    public void saveCode(HttpSession session, String email, String code) {

    	System.out.println("★★★ saveCode() 実行 ★★★");
    	System.out.println("実行時刻 = " + LocalDateTime.now());
        System.out.println("===== OTP保存処理 =====");
        System.out.println("Session ID = " + session.getId());

        session.setAttribute(CODE_KEY, code);
        session.setAttribute(EMAIL_KEY, email);

        clearTimeOut(session);

        System.out.println("有効期限 = " + session.getAttribute(EXPIRES_AT_KEY));
        System.out.println("======================");
    }

    // =====================================================
    // 認証コードを取得・有効期限確認
    // =====================================================

    public String getCode(HttpSession session) {

        synchronized (session) {

            if (isOtpExpired(session)) {
                return null;
            }

            Object code = session.getAttribute(CODE_KEY);

            return code == null ? null : code.toString();
        }
    }

    // =====================================================
    // メールアドレスを取得
    // =====================================================

    public String getEmail(HttpSession session) {

        Object email = session.getAttribute(EMAIL_KEY);

        if (email == null) {
            return null;
        }

        return email.toString();
    }

    // =====================================================
    // 認証コードを確認
    // =====================================================

    public boolean verifyCode(
            HttpSession session,
            String inputCode) {

        if (inputCode == null) {
            return false;
        }

        String savedCode = getCode(session);

        if (savedCode == null) {

            System.out.println(
                    "OTPが存在しない、または期限切れです。");

            return false;
        }

        boolean result = savedCode.equals(inputCode);

        System.out.println("========== OTP確認 ==========");
        System.out.println("入力されたOTP = " + inputCode);
        System.out.println("認証結果 = " + result);
        System.out.println("==============================");

        return result;
    }

    // =====================================================
    // 認証コードと有効期限を削除
    // =====================================================

    public void clearCode(HttpSession session) {

        session.removeAttribute(CODE_KEY);
        session.removeAttribute(EMAIL_KEY);
        session.removeAttribute(EXPIRES_AT_KEY);

        System.out.println("OTP・Email・有効期限を削除しました。");
    }

    // =====================================================
    // 有効期限を設定
    // =====================================================

    public void clearTimeOut(HttpSession session) {

        session.removeAttribute(EXPIRES_AT_KEY);

        LocalDateTime expiresAt =
                LocalDateTime.now().plusMinutes(timeout);

        session.setAttribute(
                EXPIRES_AT_KEY,
                expiresAt);

        System.out.println("===== OTP有効期限設定 =====");
        System.out.println("設定時刻 = " + LocalDateTime.now());
        System.out.println("有効期限 = " + expiresAt);
        System.out.println("設定時間 = " + timeout + "分");
    }

    // =====================================================
    // AttackSimulatorへタイムアウト通知
    // =====================================================

    private void notifyAttackSimulator() {

        try {

            String response =
                    RestClient.create()
                            .post()
                            .uri(
                                    "http://localhost:8081/attack/otp-timeout")
                            .retrieve()
                            .body(String.class);

            System.out.println(
                    "AttackSimulatorへタイムアウト通知を送信しました。");

            System.out.println(
                    "通知レスポンス = " + response);

        } catch (Exception e) {

            System.err.println(
                    "AttackSimulatorへのタイムアウト通知に失敗しました。");

            System.err.println(
                    "エラー = " + e.getMessage());
        }
    }
    
    public boolean isOtpExpired(HttpSession session) {

        synchronized (session) {

            Object code =
                    session.getAttribute(CODE_KEY);

            Object expiresAtObject =
                    session.getAttribute(EXPIRES_AT_KEY);

            System.out.println();
            System.out.println("===== OTP期限判定 =====");
            System.out.println("Session ID = " + session.getId());
            System.out.println("現在時刻 = " + LocalDateTime.now());

            // OTPが存在しない場合
            if (code == null) {

                System.out.println("OTP = 存在しません");
                System.out.println("判定 = EXPIRED");
                System.out.println("======================");

                return true;
            }

            // 有効期限が設定されていない場合
            if (!(expiresAtObject instanceof LocalDateTime)) {

                System.out.println("有効期限が設定されていません。");

                clearCode(session);

                System.out.println("判定 = EXPIRED");
                System.out.println("======================");

                return true;
            }

            LocalDateTime expiresAt =
                    (LocalDateTime) expiresAtObject;

            LocalDateTime now =
                    LocalDateTime.now();

            long remainingSeconds =
                    java.time.Duration.between(
                            now,
                            expiresAt).getSeconds();

            System.out.println("有効期限 = " + expiresAt);
            System.out.println("残り時間 = " + remainingSeconds + "秒");

            // 期限切れ判定
            if (!now.isBefore(expiresAt)) {

                System.out.println("OTPの有効期限切れを検知しました。");

                clearCode(session);

                System.out.println("判定 = EXPIRED");
                System.out.println("======================");

                return true;
            }

            System.out.println("判定 = ACTIVE");
            System.out.println("======================");

            return false;
        }
    }
}
