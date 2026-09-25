package com.example.newauthlab.controller;

import java.net.URI;
import java.util.Optional;

import jakarta.servlet.http.HttpSession;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.example.newauthlab.entity.User;
import com.example.newauthlab.repository.UserRepository;
import com.example.newauthlab.service.AttackLoginTicketService;
import com.example.newauthlab.service.MailService;
import com.example.newauthlab.service.VerificationCodeService;

@RestController
public class TwoFactorAttackController {

	private final UserRepository userRepository;

	private final PasswordEncoder passwordEncoder;

	private final MailService mailService;

	private final VerificationCodeService verificationCodeService;

	private final AttackLoginTicketService attackLoginTicketService;

	public TwoFactorAttackController(
			UserRepository userRepository,
			PasswordEncoder passwordEncoder,
			MailService mailService,
			VerificationCodeService verificationCodeService,
			AttackLoginTicketService attackLoginTicketService) {

		this.userRepository =
				userRepository;

		this.passwordEncoder =
				passwordEncoder;

		this.mailService =
				mailService;

		this.verificationCodeService =
				verificationCodeService;

		this.attackLoginTicketService =
				attackLoginTicketService;
	}

	// =========================================================
	// AttackSimulator用
	// Password認証
	// ↓
	// OTP発行・メール送信
	// =========================================================

	@PostMapping("/login/two-factor/attack/password")
	public String twoFactorAttackPassword(
			@RequestParam String username,
			@RequestParam String password,
			HttpSession session) {

		System.out.println(
				"========================================");

		System.out.println(
				"AttackSimulator用二要素認証開始");

		System.out.println(
				"username = "
						+ username);

		System.out.println(
				"========================================");

		// =====================================================
		// ユーザー検索
		// =====================================================

		Optional<User> optionalUser =
				userRepository.findByUsername(
						username);

		if (optionalUser.isEmpty()) {

			System.out.println(
					"ユーザーが存在しません。");

			return "PASSWORD_FAILED";
		}

		User user =
				optionalUser.get();

		// =====================================================
		// Password確認
		// =====================================================

		if (!passwordEncoder.matches(
				password,
				user.getPassword())) {

			System.out.println(
					"Password認証に失敗しました。");

			return "PASSWORD_FAILED";
		}

		// =====================================================
		// 二要素認証対象ユーザーを保存
		// =====================================================

		session.setAttribute(
				"twoFactorUsername",
				user.getUsername());

		session.setAttribute(
				"fromAttackSimulator",
				true);

		// =====================================================
		// OTP生成
		// =====================================================

		String code =
				mailService.generateCode();

		// =====================================================
		// OTP保存
		// =====================================================

		verificationCodeService.saveCode(
				session,
				user.getEmail(),
				code);

		// =====================================================
		// OTPメール送信
		// =====================================================

		mailService.sendVerificationCode(
				user.getEmail(),
				code);

		System.out.println(
				"email = "
						+ user.getEmail());

		System.out.println(
				"OTPを送信しました。");

		System.out.println(
				"========================================");

		// =====================================================
		// AttackSimulatorへ返す
		// =====================================================

		return "OTP_SENT";
	}

	// =========================================================
	// AttackSimulator用
	// OTP確認
	// =========================================================

	@PostMapping("/login/two-factor/attack/verify-otp")
	public ResponseEntity<Void> verifyTwoFactorAttackOtp(
			@RequestParam String otp,
			HttpSession session) {

		System.out.println(
				"========================================");

		System.out.println(
				"AttackSimulator用OTP確認");

		System.out.println(
				"OTP = "
						+ otp);

		System.out.println(
				"========================================");

		// =====================================================
		// セッション確認
		// =====================================================

		if (session == null) {

			System.out.println(
					"セッションがありません。");

			return ResponseEntity
					.status(HttpStatus.UNAUTHORIZED)
					.build();
		}

		// =====================================================
		// ユーザー名取得
		// =====================================================

		Object usernameObject =
				session.getAttribute(
						"twoFactorUsername");

		if (usernameObject == null) {

			System.out.println(
					"twoFactorUsernameがありません。");

			return ResponseEntity
					.status(HttpStatus.UNAUTHORIZED)
					.build();
		}

		String username =
				usernameObject.toString();

		// =====================================================
		// AttackSimulator経由か確認
		// =====================================================

		Object attackSimulatorObject =
				session.getAttribute(
						"fromAttackSimulator");

		if (!Boolean.TRUE.equals(
				attackSimulatorObject)) {

			System.out.println(
					"AttackSimulatorフラグがありません。");

			return ResponseEntity
					.status(HttpStatus.FORBIDDEN)
					.build();
		}

		// =====================================================
		// OTP確認
		// =====================================================

		boolean verified =
				verificationCodeService.verifyCode(
						session,
						otp);

		if (!verified) {

			System.out.println(
					"OTP認証失敗");

			System.out.println(
					"========================================");

			return ResponseEntity
					.status(HttpStatus.UNAUTHORIZED)
					.build();
		}

		// =====================================================
		// ログインチケット発行
		// =====================================================

		String ticket =
				attackLoginTicketService.createTicket(
						username);

		// =====================================================
		// OTP・二要素認証情報を削除
		// =====================================================

		verificationCodeService.clearCode(
				session);

		session.removeAttribute(
				"twoFactorUsername");

		session.removeAttribute(
				"fromAttackSimulator");

		// =====================================================
		// 成功ログ
		// =====================================================

		System.out.println(
				"OTP認証成功");

		System.out.println(
				"username = "
						+ username);

		System.out.println(
				"ticket = "
						+ ticket);

		System.out.println(
				"========================================");

		// =====================================================
		// 本物のHTTP 302リダイレクト
		// =====================================================

		return ResponseEntity
				.status(HttpStatus.FOUND)
				.location(
						URI.create(
								"/attack-login?ticket="
										+ ticket))
				.build();
	}
}