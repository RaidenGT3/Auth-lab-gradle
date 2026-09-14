package com.example.newauthlab.service;

import org.springframework.stereotype.Service;

import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;

@Service
public class TotpService {

    private final GoogleAuthenticator googleAuthenticator;

    public TotpService() {
        this.googleAuthenticator = new GoogleAuthenticator();
    }

    /**
     * Google Authenticator用の秘密鍵を生成する
     */
    public String generateSecretKey() {

        GoogleAuthenticatorKey key =
                googleAuthenticator.createCredentials();

        return key.getKey();
    }

    /**
     * Google Authenticator登録用のQRコードURLを生成する
     */
    public String generateQrCodeUrl(
            String appName,
            String username,
            String secretKey) {

        return "otpauth://totp/"
                + appName
                + ":"
                + username
                + "?secret="
                + secretKey
                + "&issuer="
                + appName;
    }

    /**
     * Google Authenticatorの6桁コードを確認する
     */
    public boolean verifyCode(
            String secretKey,
            int code) {

        return googleAuthenticator.authorize(
                secretKey,
                code
        );
    }
}