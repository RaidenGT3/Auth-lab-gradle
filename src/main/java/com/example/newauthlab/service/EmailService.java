package com.example.newauthlab.service;

import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

	private final JavaMailSender mailSender;
	
	public EmailService(JavaMailSender mailSender) {
		this.mailSender = mailSender;
	}
	
	
	public void sendOtp(String to,String otp) {
		SimpleMailMessage message = new SimpleMailMessage();
		
//		メール送信の宛先等の入力
		message.setTo(to);
		message.setSubject("ワンタイムパスワード");
		message.setText(
				"あなたのワンタイムパスワードは\n\n"
				+otp
				+"\n\nこのコードを入力してください。"
				);
//		送信
        mailSender.send(message);


	}
	
}
