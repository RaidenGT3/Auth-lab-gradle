
package com.example.newauthlab.controller;

import java.util.List;
import java.util.Optional;

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
import com.example.newauthlab.service.VerificationCodeService;

@Controller
public class EmailController {

	private final EmailService emailService;
	private final UserRepository userRepository;
	private final AttackLoginTicketService attackLoginTicketService;
	private final VerificationCodeService verificationCodeService;

//	使用するクラスを受け取るコンストラクタ
	public EmailController(
			EmailService emailService,
			UserRepository userRepository,
			AttackLoginTicketService attackLoginTicketService,
			VerificationCodeService verificationCodeService) {

		this.emailService = emailService;
		this.userRepository = userRepository;
		this.attackLoginTicketService = attackLoginTicketService;
		this.verificationCodeService = verificationCodeService;
	}
//===================================
//メールアドレス入力画面
//===================================
	
	@GetMapping("/email")
	public String email() {
		return "email";
	}

//==================================================================	
//    ユーザー名から登録メールアドレスを取得してOTPを送信
//==================================================================
	
	@PostMapping("/send-otp")
	public String sendOtp(
			@RequestParam("username") String username,
			@RequestParam(value = "fromAttackSimulator", required = false) String fromAttackSimulator,
			HttpSession session,
			Model model) {

		Optional<User> optionalUser = userRepository.findByUsername(username);

		if (optionalUser.isEmpty()) {
			model.addAttribute("error", "ユーザーが見つかりません");
			return "email";
		}

		User user = optionalUser.get();
		String email = user.getEmail();

		if (email == null || email.isBlank()) {
			model.addAttribute("error", "メールアドレスが登録されていません");
			return "email";
		}

		String otp = String.format(
				"%06d",
				new java.security.SecureRandom().nextInt(1000000));

		verificationCodeService.saveCode(session, email, otp);

		session.setAttribute("username", username);
		session.setAttribute("email", email);
		session.setAttribute(
				"fromAttackSimulator",
				"true".equals(fromAttackSimulator));

		emailService.sendOtp(email, otp);

		System.out.println("OTP送信完了");
		System.out.println("Username = " + username);
		System.out.println("送信先Email = " + email);
		System.out.println("Session ID = " + session.getId());

		return "otp";
	}

//====================================	
//	OTP入力画面
//====================================
	
	@GetMapping("/otp")
	public String otp() {
		return "otp";
	}
	
//===========================================================
//	OTPを検証し、通常ログイン、攻撃シミュレーターへ接続
//===========================================================
	
	@PostMapping("/verify-otp")
	public String verifyOtp(
			@RequestParam("otp") String otp,
			HttpSession session,
			HttpServletRequest request,
			HttpServletResponse response,
			Model model) {

		boolean verified = verificationCodeService.verifyCode(session, otp);

		if (!verified) {
			model.addAttribute(
					"error",
					"認証コードが正しくないか、有効期限が切れています");
			return "otp";
		}

		String username = (String) session.getAttribute("username");

		if (username == null || username.isBlank()) {
			verificationCodeService.clearCode(session);
			model.addAttribute("error", "ユーザー名が確認できません");
			return "otp";
		}

		Optional<User> optionalUser = userRepository.findByUsername(username);

		if (optionalUser.isEmpty()) {
			verificationCodeService.clearCode(session);
			model.addAttribute("error", "ユーザーが見つかりません");
			return "otp";
		}

		User user = optionalUser.get();

		boolean fromAttackSimulator = Boolean.TRUE.equals(
				session.getAttribute("fromAttackSimulator"));

		verificationCodeService.clearCode(session);

		session.removeAttribute("fromAttackSimulator");
		session.removeAttribute("email");
		session.removeAttribute("username");

		if (fromAttackSimulator) {
			String ticket = attackLoginTicketService.createTicket(
					user.getUsername());

			return "redirect:/attack-login?ticket=" + ticket;
		}

		loginSuccess(user, request, response);
		return "redirect:/home";
	}
	
	
//=========================================
//	Spring Securityにログイン状態を登録
//=========================================
	
	private void loginSuccess(
			User user,
			HttpServletRequest request,
			HttpServletResponse response) {

		var authentication = new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
				user.getUsername(),
				null,
				List.of(
						new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_USER")));

		var securityContext = org.springframework.security.core.context.SecurityContextHolder
				.createEmptyContext();

		securityContext.setAuthentication(authentication);

		org.springframework.security.core.context.SecurityContextHolder
				.setContext(securityContext);

		var securityContextRepository = new org.springframework.security.web.context.HttpSessionSecurityContextRepository();

		securityContextRepository.saveContext(
				securityContext,
				request,
				response);
	}
	
//=========================
//	ログイン成功画面
//=========================	
	@GetMapping("/success")
	public String success() {
		return "index";
	}
}
