package com.example.newauthlab.controller;

import java.util.Optional;

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
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.example.newauthlab.entity.User;
import com.example.newauthlab.repository.UserRepository;
import com.example.newauthlab.service.AttackLoginTicketService;

@Controller
public class AttackLoginController {

	private final AttackLoginTicketService
	attackLoginTicketService;

	private final UserRepository
	userRepository;

	public AttackLoginController(
			AttackLoginTicketService attackLoginTicketService,
			UserRepository userRepository) {

		this.attackLoginTicketService =
				attackLoginTicketService;

		this.userRepository =
				userRepository;
	}

	// =========================================================
	// attacksimulatorからのログイン引き継ぎ
	// =========================================================

	@GetMapping("/attack-login")
	public String attackLogin(
			@RequestParam("ticket") String ticket,
			HttpServletRequest request,
			HttpServletResponse response) {

		// =====================================================
		// チケット確認
		// =====================================================

		String username =
				attackLoginTicketService
				.consumeTicket(ticket);

		if (username == null) {

			return "redirect:/login";
		}

		// =====================================================
		// ユーザー取得
		// =====================================================

		Optional<User> optionalUser =
				userRepository.findByUsername(username);

		if (optionalUser.isEmpty()) {

			return "redirect:/login";
		}

		User user =
				optionalUser.get();

		// =====================================================
		// Spring Securityへログイン状態を設定
		// =====================================================

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

		// =====================================================
		// セッションへSecurityContextを保存
		// =====================================================

		HttpSession session =
				request.getSession(true);

		HttpSessionSecurityContextRepository
		securityContextRepository =
		new HttpSessionSecurityContextRepository();

		securityContextRepository.saveContext(
				securityContext,
				request,
				response);

		// =====================================================
		// attacksimulator経由であることを記録
		// =====================================================

		session.setAttribute(
				"fromAttackSimulator",
				true);

		// =====================================================
		// /homeへ
		// =====================================================

		return "redirect:/home";
	}
}