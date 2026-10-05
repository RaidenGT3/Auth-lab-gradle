package com.example.newauthlab.service;

import java.time.LocalDateTime;

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
	//セッションに保存する有効期限のキー＿なぎ
	private static final String EXPIRES_AT_KEY =
	        "twoStageVerificationExpiresAt";

	// =========================
	// 認証コードを保存
	// =========================

	public void saveCode(
			HttpSession session,
			String email,
			String code) {
		
		session.setAttribute(CODE_KEY, code);
		session.setAttribute(EMAIL_KEY, email);
		
		
		// 認証コードの有効期限を[timeout]分後に設定_なぎ
		int timeout = 1;//タイムアウトの分数を記録＿なぎ
		LocalDateTime expiresAt =
		        LocalDateTime.now().plusMinutes(timeout);
		// セッションに有効期限を保存＿なぎ
		session.setAttribute(EXPIRES_AT_KEY, expiresAt);
	}


	// =========================
	// 認証コードを取得
	// =========================

	public String getCode(
			HttpSession session) {

		//認証コードがnullではないかを判定する
		Object code =
				session.getAttribute(CODE_KEY);

		if (code == null) {
			return null;
		}
		
		
		//認証コードが有効期限内か判定する＿なぎ
		LocalDateTime expiresAt =
		        (LocalDateTime) session.getAttribute(EXPIRES_AT_KEY);
		System.out.println(LocalDateTime.now().isAfter(expiresAt));

		if (expiresAt == null) {
			System.out.println("有効期限が設定されていません。");
		    return null;
		}
		//もし認証コードが有効期限内じゃないなら
		if (LocalDateTime.now().isAfter(expiresAt)) {
		    clearCode(session);
		    return  "時間切れ";
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
