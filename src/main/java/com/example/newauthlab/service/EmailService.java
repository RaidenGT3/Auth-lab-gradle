package com.example.newauthlab.service;

import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

	private final JavaMailSender mailSender;
	private final VerificationCodeService verificationCodeService;
	public EmailService(JavaMailSender mailSender,
			VerificationCodeService verificationCodeService) {
		this.mailSender = mailSender;
		this.verificationCodeService = verificationCodeService;
	}

	public void sendOtp(String to,String otp) {
		SimpleMailMessage message = new SimpleMailMessage();
		int timeout = verificationCodeService.timeout;
		//		メール送信の宛先等の入力
		message.setTo(to);
		message.setSubject("認証コードのお知らせ");
		message.setText(
				"ログインに必要な認証コードをお知らせします。\n\n"
						+"認証コード："+otp
						+"\n\nこのコードをログイン画面に入力してください。"
						+"\n\nこのコードの有効期限は"+timeout +"分です。"
				);
		//		送信
		mailSender.send(message);


	}

}
