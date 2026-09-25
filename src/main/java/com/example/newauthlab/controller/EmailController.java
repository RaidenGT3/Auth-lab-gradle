package com.example.newauthlab.controller;

import java.util.Optional;
import java.util.Random;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.example.newauthlab.entity.User;
import com.example.newauthlab.repository.UserRepository;
import com.example.newauthlab.service.AttackLoginTicketService;
import com.example.newauthlab.service.EmailService;

@Controller
public class EmailController {

	private final EmailService emailService;

	private final UserRepository userRepository;

	private final AttackLoginTicketService
	attackLoginTicketService;

	public EmailController(
			EmailService emailService,
			UserRepository userRepository,
			AttackLoginTicketService attackLoginTicketService) {

		this.emailService =
				emailService;

		this.userRepository =
				userRepository;

		this.attackLoginTicketService =
				attackLoginTicketService;
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
			@RequestParam(
					value = "fromAttackSimulator",
					required = false)
			String fromAttackSimulator,
			HttpSession session) {

		// =====================================================
		// 6桁のランダムなOTPを作成
		// =====================================================

		String otp =
				String.format(
						"%06d",
						new Random().nextInt(1000000));

		// =====================================================
		// セッションに保存
		// =====================================================

		session.setAttribute(
				"otp",
				otp);

		session.setAttribute(
				"email",
				email);

		// =====================================================
		// attacksimulatorから来たことを記録
		// =====================================================

		if ("true".equals(fromAttackSimulator)) {

			session.setAttribute(
					"fromAttackSimulator",
					true);
		} else {

			session.removeAttribute(
					"fromAttackSimulator");
		}

		// =====================================================
		// メール送信
		// =====================================================

		emailService.sendOtp(
				email,
				otp);

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
	// OTP確認
	// =========================================================

	@PostMapping("/verify-otp")
	public String verifyOtp(
			@RequestParam("otp") String otp,
			HttpSession session,
			HttpServletRequest request,
			HttpServletResponse response,
			Model model) {

		// =====================================================
		// セッションからOTP取得
		// =====================================================

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
		// OTP削除
		// =====================================================

		session.removeAttribute("otp");

		// =====================================================
		// メールアドレス取得
		// =====================================================

		String email =
				(String) session.getAttribute("email");

		if (email == null
				|| email.isBlank()) {

			model.addAttribute(
					"error",
					"メールアドレスが確認できません");

			return "otp";
		}

		// =====================================================
		// User取得
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
		// attacksimulator経由か確認
		// =====================================================

		boolean fromAttackSimulator =
				Boolean.TRUE.equals(
						session.getAttribute(
								"fromAttackSimulator"));

		// =====================================================
		// attacksimulator経由
		// =====================================================

		if (fromAttackSimulator) {

			/*
			 * ここではまだ通常のブラウザセッションへ
			 * 直接ログインさせない。
			 *
			 * 一時チケットを作成して、
			 * ブラウザ側の /attack-login に渡す。
			 */

			String ticket =
					attackLoginTicketService
					.createTicket(
							user.getUsername());

			/*
			 * 使用済みの目印を削除
			 */
			session.removeAttribute(
					"fromAttackSimulator");

			session.removeAttribute(
					"email");

			/*
			 * attacksimulatorのHttpClientが
			 * このリダイレクト先を取得し、
			 * ブラウザをここへ移動させる。
			 */
			return "redirect:/attack-login?ticket="
			+ ticket;
		}

		// =====================================================
		// 通常のEmail OTPログイン
		// =====================================================

		loginSuccess(
				user,
				request,
				response);

		session.removeAttribute(
				"email");

		return "redirect:/home";
	}

	// =========================================================
	// 認証成功処理
	// =========================================================

	private void loginSuccess(
			User user,
			HttpServletRequest request,
			HttpServletResponse response) {

		org.springframework.security.core.Authentication
		authentication =
		new org.springframework.security.authentication
		.UsernamePasswordAuthenticationToken(
				user.getUsername(),
				null,
				java.util.List.of(
						new org.springframework.security
						.core.authority
						.SimpleGrantedAuthority(
								"ROLE_USER")));

		org.springframework.security.core.context.SecurityContext
		securityContext =
		org.springframework.security.core.context
		.SecurityContextHolder
		.createEmptyContext();

		securityContext.setAuthentication(
				authentication);

		org.springframework.security.core.context
		.SecurityContextHolder
		.setContext(
				securityContext);

		org.springframework.security.web.context
		.HttpSessionSecurityContextRepository
		securityContextRepository =
		new org.springframework.security.web.context
		.HttpSessionSecurityContextRepository();

		securityContextRepository.saveContext(
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