package com.example.newauthlab.controller;

import java.util.Random;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
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
	private final AttackLoginTicketService attackLoginTicketService;

	public EmailController(
			EmailService emailService,
			UserRepository userRepository,
			AttackLoginTicketService attackLoginTicketService) {

		this.emailService = emailService;
		this.userRepository = userRepository;
		this.attackLoginTicketService = attackLoginTicketService;
	}

	/**
	 * メールOTP送信
	 */
	@PostMapping("/send-otp")
	public String sendOtp(
			@RequestParam("email") String email,
			@RequestParam(
					value = "username",
					required = false) String username,
			@RequestParam(
					value = "fromAttackSimulator",
					required = false) String fromAttackSimulator,
			HttpSession session) {

		System.out.println();
		System.out.println("========================================");
		System.out.println("【DEBUG】/send-otp");
		System.out.println("========================================");
		System.out.println("受信username = " + username);
		System.out.println("受信メールアドレス = " + email);
		System.out.println("fromAttackSimulator = " + fromAttackSimulator);
		System.out.println("Session ID = " + session.getId());

		// =====================================================
		// 6桁のランダムなOTPを作成
		// =====================================================

		String otp =
				String.format(
						"%06d",
						new Random().nextInt(1000000));

		/*
		 * セッションにOTPとメールアドレスを保存
		 */
		session.setAttribute("otp", otp);
		session.setAttribute("email", email);

		/*
		 * AttackSimulatorからのリクエストかどうかを保存
		 */
		if ("true".equalsIgnoreCase(fromAttackSimulator)) {

			session.setAttribute(
					"fromAttackSimulator",
					true);

			/*
			 * AttackSimulatorでは
			 * usernameをユーザー識別用として保存
			 */
			session.setAttribute(
					"username",
					username);

		} else {

			session.removeAttribute(
					"fromAttackSimulator");

			session.removeAttribute(
					"username");
		}

		/*
		 * DEBUG
		 */
		System.out.println(
				"【DEBUG】生成OTP = " + otp);

		System.out.println(
				"【DEBUG】sessionに保存したOTP = "
						+ session.getAttribute("otp"));

		System.out.println(
				"【DEBUG】sessionに保存したemail = "
						+ session.getAttribute("email"));

		System.out.println(
				"【DEBUG】sessionに保存したusername = "
						+ session.getAttribute("username"));

		System.out.println(
				"【DEBUG】fromAttackSimulator = "
						+ session.getAttribute(
								"fromAttackSimulator"));

		System.out.println(
				"【DEBUG】Session ID = "
						+ session.getId());

		/*
		 * メール送信
		 */
		emailService.sendOtp(
				email,
				otp);

		System.out.println(
				"【DEBUG】OTPメール送信完了");

		System.out.println(
				"========================================");
		System.out.println();

		return "otp";
	}

	/**
	 * メールOTP検証
	 */
	@PostMapping("/verify-otp")
	public String verifyOtp(
			@RequestParam("otp") String otp,
			HttpSession session,
			HttpServletRequest request,
			HttpServletResponse response,
			Model model) {

		System.out.println();
		System.out.println("========================================");
		System.out.println("【DEBUG】/verify-otp");
		System.out.println("========================================");

		/*
		 * セッションから保存済みOTPを取得
		 */
		String savedOtp =
				(String) session.getAttribute("otp");

		String email =
				(String) session.getAttribute("email");

		String username =
				(String) session.getAttribute("username");

		Object fromAttackSimulator =
				session.getAttribute(
						"fromAttackSimulator");

		/*
		 * DEBUG
		 */
		System.out.println(
				"【DEBUG】Session ID = "
						+ session.getId());

		System.out.println(
				"【DEBUG】入力されたOTP = "
						+ otp);

		System.out.println(
				"【DEBUG】セッション保存OTP = "
						+ savedOtp);

		System.out.println(
				"【DEBUG】セッション保存email = "
						+ email);

		System.out.println(
				"【DEBUG】セッション保存username = "
						+ username);

		System.out.println(
				"【DEBUG】fromAttackSimulator = "
						+ fromAttackSimulator);

		/*
		 * OTPが間違っている場合
		 */
		if (savedOtp == null
				|| !savedOtp.equals(otp)) {

			System.out.println(
					"【DEBUG】OTP認証結果 = 不正解");

			System.out.println(
					"【DEBUG】savedOtp == null : "
							+ (savedOtp == null));

			if (savedOtp != null) {

				System.out.println(
						"【DEBUG】OTP一致判定 : "
								+ savedOtp.equals(otp));
			}

			System.out.println(
					"========================================");
			System.out.println();

			model.addAttribute(
					"error",
					"認証コードが正しくありません");

			return "otp";
		}

		/*
		 * OTPが正しい場合
		 */
		System.out.println(
				"【DEBUG】OTP認証結果 = 正解！！！！！！");

		/*
		 * OTPは使用済みなので削除
		 */
		session.removeAttribute("otp");

		/*
		 * AttackSimulatorからの認証か確認
		 */
		if (Boolean.TRUE.equals(
				session.getAttribute(
						"fromAttackSimulator"))) {

			System.out.println(
					"【DEBUG】AttackSimulatorからの認証です");

			/*
			 * usernameからユーザーを検索
			 *
			 * emailでは検索しない。
			 *
			 * emailは重複可能だが、
			 * usernameをユーザー識別子として使用する。
			 */
			User user = null;

			if (username != null
					&& !username.isBlank()) {

				user =
						userRepository
						.findByUsername(username)
						.orElse(null);
			}

			if (user == null) {

				System.out.println(
						"【DEBUG】ユーザーが見つかりません");

				System.out.println(
						"【DEBUG】検索username = "
								+ username);

				System.out.println(
						"========================================");
				System.out.println();

				model.addAttribute(
						"error",
						"ユーザーが見つかりません");

				return "otp";
			}

			System.out.println(
					"【DEBUG】ユーザー発見");

			System.out.println(
					"【DEBUG】username = "
							+ user.getUsername());

			System.out.println(
					"【DEBUG】email = "
							+ user.getEmail());

			/*
			 * AttackSimulator用ログインチケットを作成
			 */
			String ticket =
					attackLoginTicketService
					.createTicket(
							user.getUsername());

			System.out.println(
					"【DEBUG】AttackLogin Ticket作成");

			System.out.println(
					"【DEBUG】ticket = "
							+ ticket);

			/*
			 * AttackSimulator用セッション情報を削除
			 */
			session.removeAttribute(
					"fromAttackSimulator");

			session.removeAttribute(
					"email");

			session.removeAttribute(
					"username");

			/*
			 * リダイレクト先
			 */
			String redirectUrl =
					"/attack-login?ticket="
							+ ticket;

			System.out.println(
					"【DEBUG】リダイレクト先 = "
							+ redirectUrl);

			System.out.println(
					"【DEBUG】HTTP Status = 302");

			System.out.println(
					"========================================");
			System.out.println();

			return "redirect:" + redirectUrl;
		}

		/*
		 * 通常ログインの場合
		 */
		System.out.println(
				"【DEBUG】通常のOTP認証です");

		/*
		 * 通常ログインではセッションに
		 * 認証済みメールアドレスを保存
		 */
		session.setAttribute(
				"authenticatedEmail",
				email);

		/*
		 * メールアドレス情報は不要なので削除
		 */
		session.removeAttribute("email");

		System.out.println(
				"【DEBUG】通常ログイン成功");

		System.out.println(
				"【DEBUG】authenticatedEmail = "
						+ session.getAttribute(
								"authenticatedEmail"));

		System.out.println(
				"========================================");
		System.out.println();

		return "redirect:/login";
	}
}