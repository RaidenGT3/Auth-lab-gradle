package com.example.newauthlab.controller;

import jakarta.servlet.http.HttpSession;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.example.newauthlab.entity.User;
import com.example.newauthlab.repository.UserRepository;

@Controller
public class AuthController {

	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;

	public AuthController(
			UserRepository userRepository,
			PasswordEncoder passwordEncoder) {

		this.userRepository = userRepository;
		this.passwordEncoder = passwordEncoder;
	}

	// =========================
	// 認証選択画面
	// =========================

	@GetMapping({ "/", "/auth" })
	public String authSelect() {
		return "auth-select";
	}

	// =========================
	// 認証方式選択処理
	// =========================

	@PostMapping("/auth/select")
	public String selectAuth(
			@RequestParam String authType,
			HttpSession session) {

		switch (authType) {

		// 一段階認証
		case "one-stage":
			return "redirect:/login/one-stage";

		// 二段階認証
		case "two-stage":
			session.setAttribute("authState", "two-stage");
			return "redirect:/login";

		// 三段階認証
		case "three-stage":
			session.setAttribute("authState", "three-stage-now-step1");

			return "redirect:/login";

		// 一要素認証
		case "one-factor":
			return "redirect:/login/one-factor";

		// 二要素認証
		case "two-factor":
			return "redirect:/login/two-factor";

		// 三要素認証
		case "three-factor":
			// セッションにPOSTで贈られた値を入れる

			session.setAttribute("authState", "three-factor-now-step1");
			return "redirect:/login";

		// 想定外の値が送られた場合
		default:
			return "redirect:/auth";
		}
	}

	// =========================
	// 一段階認証ログイン画面
	// =========================

	@GetMapping("/login/one-stage")
	public String oneStageLogin() {
		return "login";
	}



	@GetMapping("/password")
	public String password() {
		return "password";
	}


	// =========================
	// 一要素認証ログイン画面
	// =========================

	@GetMapping("/login/one-factor")
	public String oneFactorLogin() {
		return "login/one-factor";
	}

	// =========================
	// 二要素認証ログイン画面
	// =========================

	@GetMapping("/login/two-factor")
	public String twoFactorLogin() {
		return "login/two-factor";
	}

	// =========================
	// 三要素認証ログイン画面
	// =========================

	@GetMapping("/login/three-factor")
	public String threeFactorLogin() {
		return "login/three-factor";
	}

	// =========================
	// 通常ログイン画面
	// =========================

	@GetMapping("/login")
	public String login() {
		return "login";
	}

	// =========================
	// ユーザー登録画面
	// =========================

	@GetMapping("/register")
	public String register() {
		return "register";
	}

	// =========================
	// ユーザー登録処理
	// =========================

	@PostMapping("/register")
	public String registerUser(
			@RequestParam String username,
			@RequestParam String password1,
			@RequestParam String password2,
			@RequestParam String password3,
			Model model) {

		// ユーザー名がすでに存在するか確認
		if (userRepository.existsByUsername(username)) {

			model.addAttribute(
					"error",
					"そのユーザー名はすでに使用されています");

			return "register";
		}

		// 新しいユーザーを作成
		User user = new User();

		user.setUsername(username);

		// パスワードをBCryptで暗号化
		user.setPassword1_Hash(
				passwordEncoder.encode(password1));
		// パスワードをBCryptで暗号化
		user.setPassword2_Hash(
				passwordEncoder.encode(password2));
		// パスワードをBCryptで暗号化
		user.setPassword3_Hash(
				passwordEncoder.encode(password3));

		// データベースへ保存
		userRepository.save(user);

		// 登録後はログイン画面へ
		return "redirect:/login";
	}

	@PostMapping("/password")
	public String checkSecondPassword(
			@RequestParam("password") String inputPassword,
			HttpSession session) {

		//セッションを取り出す　取り出したセッションにより２回目以降の認証を決定する
		String authState = (String) session.getAttribute("authState");
		String username = (String) session.getAttribute("loginUsername");

		User user = userRepository.findByUsername(username)
				.orElseThrow();

		switch (authState) {

		// =========================
		// 多段階認証
		// =========================
		case "two-stage":
			//二段階認証の２つ目のパスワードを比較
			if (passwordEncoder.matches(inputPassword, user.getPassword2_hash())) {
				//パスワードが一致した場合はログイン成功
				return "redirect:/index";
			}
			return "password";
			
		case "three-stage-now-step1":
			//三段階認証の２つ目のパスワードを比較
			if (passwordEncoder.matches(inputPassword, user.getPassword2_hash())) {
				//パスワードが一致した場合は三段階目へ
				session.setAttribute("authState", "three-stage-now-step2");
				return "redirect:/password";
			}
			return "redirect:/auth";
			
		case "three-stage-now-step2":
			//三段階認証の３つ目のパスワードを比較
			if (passwordEncoder.matches(inputPassword, user.getPassword3_hash())) {
				//パスワードが一致した場合はログイン成功
				return "redirect:/index";
			}
			return "redirect:/auth";
		}
		return "redirect:/password";
	}

	// =========================
	// 2要素認証の組み合わせをセッションに保存する
	// =========================
	@PostMapping("/login/two-factor")
	public String selectTwoFactor(
			@RequestParam String authType,
			HttpSession session) {

		// セッションにPOSTで贈られた値を入れる
		session.setAttribute("authState", authType);

		if (authType.equals("possession-biometric")) {
			//所有　+生体
			return "redirect:/email";

		} else if (authType.equals("knowledge-possession")) {
			//知識　+　所有
			return "redirect:/login";
		} else if (authType.equals("knowledge-biometric")) {
			//知識　＋　生体
			return "redirect:/login";
		}

		return "redirect:/login/two-factor";
	}
}