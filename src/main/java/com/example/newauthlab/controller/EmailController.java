package com.example.newauthlab.controller;

import java.util.Optional;
import java.util.Random;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.example.newauthlab.entity.User;
import com.example.newauthlab.repository.UserRepository;
import com.example.newauthlab.service.EmailService;

@Controller
public class EmailController {

	private final EmailService emailService;

	private final UserRepository userRepository;

	public EmailController(
			EmailService emailService,
			UserRepository userRepository) {

		this.emailService =
				emailService;

		this.userRepository =
				userRepository;
	}

	// =========================================================
	// メールアドレス入力画面
	// =========================================================

	@GetMapping("/email")
	public String email() {
		return "email";
	}

	// =========================================================
	// OTPを送信
	// =========================================================

	@PostMapping("/send-otp")
	public String sendOtp(
			@RequestParam("email") String email,
			HttpSession session) {

		// 6桁のランダムなOTPを作成
		String otp =
				String.format(
						"%06d",
						new Random().nextInt(1000000));

		// OTPをセッションに保存
		session.setAttribute(
				"otp",
				otp);

		// メールアドレスもセッションに保存
		session.setAttribute(
				"email",
				email);

		// メール送信
		emailService.sendOtp(
				email,
				otp);

		// OTP入力画面へ
		return "otp";
	}

	// =========================================================
	// OTP入力画面
	// =========================================================

	@GetMapping("/otp")
	public String otp() {
		return "otp";
	}

	// =========================================================
	// OTPを確認
	// =========================================================

	@PostMapping("/verify-otp")
	public String verifyOtp(
			@RequestParam("otp") String otp,
			HttpSession session,
			HttpServletRequest request,
			HttpServletResponse response,
			Model model) {

		// セッションに保存しているOTPを取得
		String savedOtp =
				(String) session.getAttribute("otp");

		// =====================================================
		// OTP不正
		// =====================================================

		if (savedOtp == null
				|| !savedOtp.equals(otp)) {

			model.addAttribute(
					"error",
					"認証コードが正しくありません");

			return "otp";
		}

		// =====================================================
		// OTP成功
		// =====================================================

		session.removeAttribute("otp");

		String email =
				(String) session.getAttribute("email");

		if (email == null || email.isBlank()) {

			model.addAttribute(
					"error",
					"メールアドレスが確認できません");

			return "otp";
		}

		// =====================================================
		// メールアドレスからユーザー取得
		// =====================================================

		Optional<User> optionalUser =
				userRepository.findByEmail(email);

		if (optionalUser.isEmpty()) {

			model.addAttribute(
					"error",
					"ユーザーが見つかりません");

			return "otp";
		}

		User user =
				optionalUser.get();

		// =====================================================
		// 実ログイン
		// =====================================================

		loginSuccess(
				user,
				request,
				response);

		// メールアドレスは不要になったので削除
		session.removeAttribute("email");

		// =====================================================
		// 既存の多要素認証処理
		// =====================================================

		String authState =
				(String) session.getAttribute(
						"authState");

		// 3要素認証の2回目（所有認証）
		if ("three-factor-now-step2"
				.equals(authState)) {

			session.setAttribute(
					"authState",
					"three-factor-now-step3");

			return "redirect:/login";

		} else if ("possession-biometric"
				.equals(authState)) {

			return "redirect:/login";

		} else {

			// 通常のEmail OTP認証
			return "redirect:/home";
		}
	}

	// =========================================================
	// 認証成功処理
	// =========================================================

	private void loginSuccess(
			User user,
			HttpServletRequest request,
			HttpServletResponse response) {

		/*
		 * authenticatedユーザーを作成
		 *
		 * 現在のシステムではログインユーザー名を
		 * Principalとして使用する
		 */
		Authentication authentication =
				new UsernamePasswordAuthenticationToken(
						user.getUsername(),
						null,
						java.util.List.of(
								new SimpleGrantedAuthority(
										"ROLE_USER")));

		SecurityContext securityContext =
				SecurityContextHolder.createEmptyContext();

		securityContext.setAuthentication(
				authentication);

		SecurityContextHolder.setContext(
				securityContext);

		/*
		 * HttpSessionへSecurityContextを保存
		 */
		HttpSessionSecurityContextRepository
		securityContextRepository =
		new HttpSessionSecurityContextRepository();

		securityContextRepository
		.saveContext(
				securityContext,
				request,
				response);
	}

	// =========================================================
	// 認証成功画面
	// =========================================================

	@GetMapping("/success")
	public String success() {
		return "index";
	}
}