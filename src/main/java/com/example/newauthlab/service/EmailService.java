
package com.example.newauthlab.service;

import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

	private final JavaMailSender mailSender;

	private final VerificationCodeService verificationCodeService;

	public EmailService(
			JavaMailSender mailSender,
			VerificationCodeService verificationCodeService) {

		this.mailSender = mailSender;
		this.verificationCodeService = verificationCodeService;
	}

	// =========================
	// OTP送信
	// =========================

	public void sendOtp(String to, String otp) {

		// OTP有効期限を取得
		int timeout = verificationCodeService.getTimeout();

		SimpleMailMessage message =
				new SimpleMailMessage();

		message.setTo(to);

		message.setSubject(
				"認証コードのお知らせ");

		message.setText(
				"ログインに必要な認証コードをお知らせします。\n\n"
						+ "認証コード：" + otp + "\n\n"
						+ "【有効期限】\n"
						+ "この認証コードの有効期限は発行から"
						+ timeout + "分間です。\n\n"
						+ "有効期限を過ぎた場合は、"
						+ "再度認証コードを発行してください。\n\n"
						+ "このコードをログイン画面に入力してください。"
				);

		// メール送信
		mailSender.send(message);

		System.out.println("===== OTPメール送信 =====");
		System.out.println("送信先 = " + to);
		System.out.println("有効期限 = " + timeout + "分");
	}
}
