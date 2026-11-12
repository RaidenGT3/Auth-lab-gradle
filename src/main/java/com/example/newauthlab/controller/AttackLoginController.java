
package com.example.newauthlab.controller;

import java.util.List;
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

	private final AttackLoginTicketService attackLoginTicketService;
	private final UserRepository userRepository;

	public AttackLoginController(
			AttackLoginTicketService attackLoginTicketService,
			UserRepository userRepository) {

		this.attackLoginTicketService = attackLoginTicketService;
		this.userRepository = userRepository;
	}

	// =========================================================
	// AttackSimulatorからのログイン引き継ぎ
	// =========================================================

	@GetMapping("/attack-login")
	public String attackLogin(
			@RequestParam("ticket") String ticket,
			HttpServletRequest request,
			HttpServletResponse response) {

		// =====================================================
		// 1. チケット確認
		// =====================================================

		String username =
				attackLoginTicketService.consumeTicket(ticket);

		if (username == null) {
			System.out.println("AttackLogin: チケットが無効です");
			return "redirect:/login";
		}

		// =====================================================
		// 2. ユーザー取得
		// =====================================================

		Optional<User> optionalUser =
				userRepository.findByUsername(username);

		if (optionalUser.isEmpty()) {
			System.out.println("AttackLogin: ユーザーが存在しません");
			return "redirect:/login";
		}

		User user = optionalUser.get();

		// =====================================================
		// 3. Authentication作成
		// =====================================================

		Authentication authentication =
				new UsernamePasswordAuthenticationToken(
						user.getUsername(),
						null,
						List.of(new SimpleGrantedAuthority("ROLE_USER"))
						);

		// =====================================================
		// 4. SecurityContext作成
		// =====================================================

		SecurityContext securityContext =
				SecurityContextHolder.createEmptyContext();

		securityContext.setAuthentication(authentication);

		SecurityContextHolder.setContext(securityContext);

		// =====================================================
		// 5. HTTPセッション取得
		// =====================================================

		HttpSession session = request.getSession(true);

		// =====================================================
		// 6. SecurityContextをセッションに保存
		// =====================================================

		session.setAttribute(
				HttpSessionSecurityContextRepository
				.SPRING_SECURITY_CONTEXT_KEY,
				securityContext
				);

		HttpSessionSecurityContextRepository repository =
				new HttpSessionSecurityContextRepository();

		repository.saveContext(
				securityContext,
				request,
				response
				);

		// =====================================================
		// 7. AttackSimulator経由のログイン情報
		// =====================================================

		session.setAttribute("fromAttackSimulator", true);

		// =====================================================
		// 8. 認証状態の確認ログ
		// =====================================================

		System.out.println("===== AttackLogin 認証確認 =====");

		System.out.println(
				"認証ユーザー: " + authentication.getName()
				);

		System.out.println(
				"認証状態: " + authentication.isAuthenticated()
				);

		System.out.println(
				"権限: " + authentication.getAuthorities()
				);

		System.out.println(
				"セッションID: " + session.getId()
				);

		System.out.println(
				"SecurityContext保存: "
						+ (session.getAttribute(
								HttpSessionSecurityContextRepository
								.SPRING_SECURITY_CONTEXT_KEY) != null)
				);

		System.out.println("================================");

		// =====================================================
		// 9. ホーム画面へ遷移
		// =====================================================

		return "redirect:/home";
	}
}
