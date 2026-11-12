
package com.example.newauthlab.service;

import java.security.SecureRandom;

import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class MailService {

	private final JavaMailSender mailSender;

	private final VerificationCodeService verificationCodeService;

	public MailService(
			JavaMailSender mailSender,
			VerificationCodeService verificationCodeService) {

		this.mailSender = mailSender;
		this.verificationCodeService = verificationCodeService;
	}

	// =========================
	// 認証コード生成
	// =========================

	public String generateCode() {

		SecureRandom random = new SecureRandom();

		int code = 100000 + random.nextInt(900000);

		return String.valueOf(code);
	}

	// =========================
	// 認証コード送信
	// =========================

	public void sendVerificationCode(
			String email,
			String code) {

		// VerificationCodeServiceから有効期限を取得
		int timeout = verificationCodeService.getTimeout();

		SimpleMailMessage message =
				new SimpleMailMessage();

		message.setTo(email);

		message.setSubject(
				"認証コードのお知らせ");

		message.setText(
				"ログインに必要な認証コードをお知らせします。\n\n"
						+ "認証コード：" + code + "\n\n"
						+ "【有効期限】\n"
						+ "この認証コードの有効期限は発行から"
						+ timeout + "分間です。\n\n"
						+ "有効期限を過ぎた場合は、"
						+ "再度認証コードを発行してください。\n\n"
						+ "このコードをログイン画面に入力してください。"
				);

		mailSender.send(message);
	}
}
