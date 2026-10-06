package com.example.newauthlab.controller;

import java.util.Collections;
import java.util.Optional;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.example.newauthlab.entity.User;
import com.example.newauthlab.repository.UserRepository;
import com.example.newauthlab.service.AttackLoginTicketService;
import com.example.newauthlab.service.MailService;
import com.example.newauthlab.service.QrCodeService;
import com.example.newauthlab.service.TotpService;
import com.example.newauthlab.service.VerificationCodeService;

@Controller
public class AuthController {

	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;
	private final MailService mailService;
	private final VerificationCodeService verificationCodeService;
	private final TotpService totpService;
	private final QrCodeService qrCodeService;
	private final AttackLoginTicketService attackLoginTicketService;

	private int missloginCount = 0;//ログイン失敗回数
	private int missLimit = 1;//ログイン失敗回数の上限
	private int limitCount = 0;//ログイン失敗回数の上限を超えた回数

	private int[] penalty_Time = new int[] {30, 60, -1};//ログイン失敗回数の上限を超えた場合の待機時間（秒）
														//-1の場合は永久ロック
	private boolean now_Lock = false;//今アカウントがロックされているかどうか

	private final SecurityContextRepository securityContextRepository =
			new HttpSessionSecurityContextRepository();

	public AuthController(
			UserRepository userRepository,
			PasswordEncoder passwordEncoder,
			MailService mailService,
			VerificationCodeService verificationCodeService,
			TotpService totpService,
			QrCodeService qrCodeService,
			AttackLoginTicketService attackLoginTicketService) {

		this.userRepository = userRepository;
		this.passwordEncoder = passwordEncoder;
		this.mailService = mailService;
		this.verificationCodeService = verificationCodeService;
		this.totpService = totpService;
		this.qrCodeService = qrCodeService;
		this.attackLoginTicketService = attackLoginTicketService;
	}

	@GetMapping("/")
	public String root() {
		return "redirect:/auth";
	}

	@GetMapping("/home")
	public String home() {
		return "index";
	}



	// =========================================================
	// 認証選択画面
	// =========================================================

	@GetMapping("/auth")
	public String authSelect() {
		return "auth-select";
	}



	// =========================================================
	// 認証方式選択
	// =========================================================

	@PostMapping("/auth/select")
	public String selectAuth(
			@RequestParam String authType) {

		//認証ペナルティをリセット
		now_Lock = false;
		missloginCount = 0;//失敗回数をリセット
		limitCount = 0;

		switch (authType) {

		case "one-stage":

			return "redirect:/login/one-stage";

		case "two-stage":

			return "redirect:/login/two-stage";

		case "three-stage":

			return "redirect:/login/three-stage";

		case "one-factor":
			return "redirect:/login/one-factor";

		case "two-factor":
			return "redirect:/login/two-factor";

		default:
			return "redirect:/auth";
		}
	}



	// =========================================================
	// 一段階認証
	// ID + Password
	// =========================================================

	@GetMapping("/login/one-stage")
	public String oneStageLogin() {
		return "login/one-stage";
	}

	@PostMapping("/login/one-stage")
	public String oneStageLoginProcess(
			@RequestParam String username,
			@RequestParam String password,
			@RequestParam(
					value = "fromAttackSimulator",
					required = false)
			String fromAttackSimulator,
			HttpServletRequest request,
			HttpServletResponse response,
			Model model) {

		Optional<User> optionalUser =
				userRepository.findByUsername(username);

		if (now_Lock) {
			model.addAttribute(
					"error",
					"アカウントが永久にロックされています。");
			return "login/one-stage";
		}

		if (optionalUser.isEmpty()) {

			model.addAttribute(
					"error",
					"ユーザー名またはパスワードが正しくありません");

			return "login/one-stage";
		}

		User user = optionalUser.get();

		if (!passwordEncoder.matches(
				password,
				user.getPassword())) {

			model.addAttribute(
					"error",
					"ユーザー名またはパスワードが正しくありません");

			Misslogin();//失敗回数カウントなど

			return "login/one-stage";
		}

		loginSuccess(user, request, response);

		if ("true".equals(fromAttackSimulator)) {

			request.getSession().setAttribute(
					"fromAttackSimulator",
					true);
		}

		return "redirect:/home";
	}



	// =========================================================
	// 二段階認証
	// Password1 → Password2
	// =========================================================

	@GetMapping("/login/two-stage")
	public String twoStageLogin() {
		return "login/two-stage";
	}

	// =========================================================
	// 二段階認証
	// Password1 → Password2
	// =========================================================

	@PostMapping("/login/two-stage")
	public String twoStageLoginProcess(
			@RequestParam String username,
			@RequestParam String password,
			@RequestParam(
					value = "fromAttackSimulator",
					required = false)
			String fromAttackSimulator,
			@RequestParam(
					value = "password2",
					required = false)
			String password2,
			HttpSession session,
			Model model) {

		// =====================================================
		// デバッグログ：二段階認証1段階目開始
		// =====================================================

		System.out.println(
				"===== NewAuthLab 二段階認証 1段階目開始 =====");

		System.out.println(
				"username = " + username);

		System.out.println(
				"password = " + password);

		System.out.println(
				"fromAttackSimulator = "
						+ fromAttackSimulator);

		System.out.println(
				"now_Lock = " + now_Lock);

		System.out.println(
				"missloginCount = "
						+ missloginCount);

		System.out.println(
				"limitCount = "
						+ limitCount);

		System.out.println(
				"============================================");

		Optional<User> optionalUser =
				userRepository.findByUsername(username);

		// =====================================================
		// デバッグログ：ユーザー検索結果
		// =====================================================

		System.out.println(
				"ユーザー存在 = "
						+ optionalUser.isPresent());

		// =====================================================
		// アカウントロック確認
		// =====================================================

		if (now_Lock) {

			System.out.println(
					"二段階認証1段階目失敗："
							+ "now_Lock = true");

			model.addAttribute(
					"error",
					"アカウントが永久にロックされています。");

			return "login/two-stage";
		}

		// =====================================================
		// ユーザー存在確認
		// =====================================================

		if (optionalUser.isEmpty()) {

			System.out.println(
					"二段階認証1段階目失敗："
							+ "ユーザーが存在しません");

			model.addAttribute(
					"error",
					"ユーザー名またはパスワードが正しくありません");

			return "login/two-stage";
		}

		User user = optionalUser.get();

		System.out.println(
				"取得ユーザー = "
						+ user.getUsername());

		// =====================================================
		// Password1確認
		// =====================================================

		boolean passwordMatches =
				passwordEncoder.matches(
						password,
						user.getPassword());

		System.out.println(
				"Password1一致 = "
						+ passwordMatches);

		if (!passwordMatches) {

			System.out.println(
					"二段階認証1段階目失敗："
							+ "Password1不一致");

			model.addAttribute(
					"error",
					"ユーザー名またはパスワードが正しくありません");

			if (Misslogin()) {//失敗回数カウントなど アカウント永久ロックでtrueを返す

				System.out.println(
						"二段階認証1段階目失敗："
								+ "Misslogin()によりアカウントロック");

				model.addAttribute(
						"error",
						"アカウントがロックされました。");
			}

			return "login/two-stage";
		}

		// =====================================================
		// 1段階目成功
		// =====================================================

		System.out.println(
				"===== 二段階認証 1段階目成功 =====");

		System.out.println(
				"username = "
						+ user.getUsername());

		System.out.println(
				"Password1 = "
						+ password);

		System.out.println(
				"=================================");

		session.setAttribute(
				"twoStageUsername",
				user.getUsername());

		// =====================================================
		// セッション保存確認
		// =====================================================

		System.out.println(
				"twoStageUsername 保存値 = "
						+ session.getAttribute(
								"twoStageUsername"));

		System.out.println(
				"JSESSIONID = "
						+ session.getId());

		// =====================================================
		// attacksimulatorから来た場合
		// =====================================================

		if ("true".equals(fromAttackSimulator)) {

			session.setAttribute(
					"fromAttackSimulator",
					true);

			System.out.println(
					"fromAttackSimulator = true");
		}

		// Password2も保存
		if ("true".equals(fromAttackSimulator)
				&& password2 != null
				&& !password2.isBlank()) {

			session.setAttribute(
					"fromAttackSimulatorPassword2",
					password2);

			System.out.println(
					"fromAttackSimulatorPassword2 = "
							+ password2);
		}

		System.out.println(
				"二段階認証1段階目："
						+ "Password2画面へリダイレクト");

		System.out.println(
				"============================================");

		return "redirect:/login/two-stage/password2";
	}



	// =========================================================
	// 二段階認証
	// Password2入力画面
	// =========================================================

	@GetMapping("/login/two-stage/password2")
	public String twoStagePassword2(
			HttpSession session) {

		System.out.println(
				"===== 二段階認証 Password2画面 =====");

		System.out.println(
				"JSESSIONID = "
						+ session.getId());

		System.out.println(
				"twoStageUsername = "
						+ session.getAttribute(
								"twoStageUsername"));

		if (session.getAttribute("twoStageUsername") == null) {

			System.out.println(
					"twoStageUsernameが存在しないため"
							+ "Password1画面へ戻ります");

			return "redirect:/login/two-stage";
		}

		System.out.println(
				"Password2画面表示成功");

		System.out.println(
				"====================================");

		return "login/two-stage-password2";
	}



	// =========================================================
	// 二段階認証
	// Password2確認
	// =========================================================

	@PostMapping("/login/two-stage/password2")
	public String verifyTwoStagePassword2(
			@RequestParam String password2,
			HttpSession session,
			HttpServletRequest request,
			HttpServletResponse response,
			Model model) {

		System.out.println(
				"===== NewAuthLab 二段階認証 2段階目開始 =====");

		System.out.println(
				"Password2 = " + password2);

		System.out.println(
				"JSESSIONID = "
						+ session.getId());

		System.out.println(
				"twoStageUsername = "
						+ session.getAttribute(
								"twoStageUsername"));

		System.out.println(
				"now_Lock = " + now_Lock);

		System.out.println(
				"============================================");

		Object usernameObject =
				session.getAttribute("twoStageUsername");

		if (usernameObject == null) {

			System.out.println(
					"二段階認証2段階目失敗："
							+ "twoStageUsernameが存在しません");

			return "redirect:/login/two-stage";
		}

		String username =
				usernameObject.toString();

		Optional<User> optionalUser =
				userRepository.findByUsername(username);

		if (optionalUser.isEmpty()) {

			System.out.println(
					"二段階認証2段階目失敗："
							+ "ユーザーが存在しません");

			session.removeAttribute(
					"twoStageUsername");

			return "redirect:/login/two-stage";
		}

		User user = optionalUser.get();

		if (now_Lock) {

			System.out.println(
					"二段階認証2段階目失敗："
							+ "now_Lock = true");

			model.addAttribute(
					"error",
					"アカウントが永久にロックされています。");

			return "login/two-stage-password2";
		}

		// Password2
		boolean password2Matches =
				passwordEncoder.matches(
						password2,
						user.getPassword2());

		System.out.println(
				"Password2一致 = "
						+ password2Matches);

		if (!password2Matches) {

			System.out.println(
					"二段階認証2段階目失敗："
							+ "Password2不一致");

			model.addAttribute(
					"error",
					"Password2が正しくありません");

			if (Misslogin()) {//失敗回数カウントなど アカウント永久ロックでtrueを返す

				System.out.println(
						"二段階認証2段階目失敗："
								+ "Misslogin()によりアカウントロック");

				model.addAttribute(
						"error",
						"アカウントがロックされました。");
			}

			return "login/two-stage-password2";
		}

		// =====================================================
		// 2段階目成功
		// =====================================================

		System.out.println(
				"===== 二段階認証 2段階目成功 =====");

		System.out.println(
				"username = " + username);

		System.out.println(
				"Password2 = " + password2);

		System.out.println(
				"ログイン成功処理を実行します");

		System.out.println(
				"=================================");

		loginSuccess(user, request, response);

		session.removeAttribute("twoStageUsername");

		System.out.println(
				"twoStageUsernameを削除しました");

		System.out.println(
				"二段階認証：/homeへリダイレクト");

		System.out.println(
				"=================================");

		return "redirect:/home";
	}



	// =========================================================
	// 三段階認証
	// Password1 → Password2 → Password3
	// =========================================================

	@GetMapping("/login/three-stage")
	public String threeStageLogin() {

		return "login/three-stage";
	}



	// =========================================================
	// 三段階認証
	// Password1確認
	// =========================================================

	@PostMapping("/login/three-stage")
	public String threeStageLoginProcess(
			@RequestParam String username,
			@RequestParam String password,
			@RequestParam(
					value = "fromAttackSimulator",
					required = false)
			String fromAttackSimulator,
			@RequestParam(
					value = "password2",
					required = false)
			String password2,
			@RequestParam(
					value = "password3",
					required = false)
			String password3,
			HttpSession session,
			Model model) {

		Optional<User> optionalUser =
				userRepository.findByUsername(username);

		if (now_Lock) {
			model.addAttribute(
					"error",
					"アカウントが永久にロックされています。");
			return "login/three-stage";
		}

		if (optionalUser.isEmpty()) {

			model.addAttribute(
					"error",
					"ユーザー名またはパスワードが正しくありません");

			return "login/three-stage";
		}

		User user = optionalUser.get();

		// =====================================================
		// Password1確認
		// =====================================================

		if (!passwordEncoder.matches(
				password,
				user.getPassword())) {

			model.addAttribute(
					"error",
					"ユーザー名またはパスワードが正しくありません");

			if (Misslogin()) {//失敗回数カウントなど アカウント永久ロックでtrueを返す

				model.addAttribute(
						"error",
						"アカウントがロックされました。");
			}

			return "login/three-stage";
		}

		// =====================================================
		// 1段階目成功
		// =====================================================

		session.setAttribute(
				"threeStageUsername",
				user.getUsername());

		// =====================================================
		// attacksimulatorから来た場合
		// =====================================================

		if ("true".equals(fromAttackSimulator)) {

			session.setAttribute(
					"fromAttackSimulator",
					true);

			if (password2 != null
					&& !password2.isBlank()) {

				session.setAttribute(
						"fromAttackSimulatorPassword2",
						password2);
			}

			if (password3 != null
					&& !password3.isBlank()) {

				session.setAttribute(
						"fromAttackSimulatorPassword3",
						password3);
			}
		}

		return "redirect:/login/three-stage/password2";
	}



	// =========================================================
	// 三段階認証
	// Password2入力画面
	// =========================================================

	@GetMapping("/login/three-stage/password2")
	public String threeStagePassword2(
			HttpSession session) {

		if (session.getAttribute(
				"threeStageUsername") == null) {

			return "redirect:/login/three-stage";
		}

		return "login/three-stage-password2";
	}



	// =========================================================
	// 三段階認証
	// Password2確認
	// =========================================================

	@PostMapping("/login/three-stage/password2")
	public String verifyThreeStagePassword2(
			@RequestParam String password2,
			HttpSession session,
			HttpServletRequest request,
			HttpServletResponse response,
			Model model) {

		Object usernameObject =
				session.getAttribute(
						"threeStageUsername");

		if (usernameObject == null) {

			return "redirect:/login/three-stage";
		}

		String username =
				usernameObject.toString();

		Optional<User> optionalUser =
				userRepository.findByUsername(username);

		if (optionalUser.isEmpty()) {

			session.removeAttribute(
					"threeStageUsername");

			return "redirect:/login/three-stage";
		}

		User user = optionalUser.get();

		// =====================================================
		// Password2確認
		// =====================================================

		if (now_Lock) {
			model.addAttribute(
					"error",
					"アカウントが永久にロックされています。");
			return "login/three-stage-password2";
		}

		if (!passwordEncoder.matches(
				password2,
				user.getPassword2())) {

			model.addAttribute(
					"error",
					"Password2が正しくありません");

			if (Misslogin()) {//失敗回数カウントなど アカウント永久ロックでtrueを返す

				model.addAttribute(
						"error",
						"アカウントがロックされました。");
			}

			return "login/three-stage-password2";
		}

		// =====================================================
		// 2段階目成功
		// =====================================================

		session.setAttribute(
				"threeStagePassword2Verified",
				true);

		return "redirect:/login/three-stage/password3";
	}



	// =========================================================
	// 三段階認証
	// Password3入力画面
	// =========================================================

	@GetMapping("/login/three-stage/password3")
	public String threeStagePassword3(
			HttpSession session) {

		if (session.getAttribute(
				"threeStageUsername") == null) {

			return "redirect:/login/three-stage";
		}

		if (session.getAttribute(
				"threeStagePassword2Verified") == null) {

			return "redirect:/login/three-stage/password2";
		}

		return "login/three-stage-password3";
	}



	// =========================================================
	// 三段階認証
	// Password3確認
	// =========================================================

	@PostMapping("/login/three-stage/password3")
	public String verifyThreeStagePassword3(
			@RequestParam String password3,
			HttpSession session,
			HttpServletRequest request,
			HttpServletResponse response,
			Model model) {

		Object usernameObject =
				session.getAttribute(
						"threeStageUsername");

		if (usernameObject == null) {

			return "redirect:/login/three-stage";
		}

		Object password2Verified =
				session.getAttribute(
						"threeStagePassword2Verified");

		if (password2Verified == null) {

			return "redirect:/login/three-stage/password2";
		}

		String username =
				usernameObject.toString();

		Optional<User> optionalUser =
				userRepository.findByUsername(username);

		if (optionalUser.isEmpty()) {

			session.removeAttribute(
					"threeStageUsername");

			session.removeAttribute(
					"threeStagePassword2Verified");

			return "redirect:/login/three-stage";
		}

		User user = optionalUser.get();

		// =====================================================
		// Password3確認
		// =====================================================

		if (now_Lock) {
			model.addAttribute(
					"error",
					"アカウントが永久にロックされています。");
			return "login/three-stage-password3";
		}

		if (!passwordEncoder.matches(
				password3,
				user.getPassword3())) {

			model.addAttribute(
					"error",
					"Password3が正しくありません");

			if (Misslogin()) {//失敗回数カウントなど アカウント永久ロックでtrueを返す

				model.addAttribute(
						"error",
						"アカウントがロックされました。");
			}

			return "login/three-stage-password3";
		}

		// =====================================================
		// 3段階目成功
		// =====================================================

		loginSuccess(
				user,
				request,
				response);

		// =====================================================
		// 一時セッション削除
		// =====================================================

		session.removeAttribute(
				"threeStageUsername");

		session.removeAttribute(
				"threeStagePassword2Verified");

		session.removeAttribute(
				"fromAttackSimulatorPassword2");

		session.removeAttribute(
				"fromAttackSimulatorPassword3");

		// fromAttackSimulatorは
		// /homeでログアウト先を判定するため残す

		return "redirect:/home";
	}



	// =========================================================
	// 一要素認証
	// Password または Email OTP
	// =========================================================

	@GetMapping("/login/one-factor")
	public String oneFactorLogin() {
		return "login/one-factor";
	}



	@PostMapping("/login/one-factor/select")
	public String selectOneFactor(
			@RequestParam String factor) {

		switch (factor) {

		case "password":
			return "redirect:/login/one-factor/password";

		case "email":
			return "redirect:/login/one-factor/email";

		default:
			return "redirect:/login/one-factor";
		}
	}



	// =========================================================
	// 一要素認証 - Password
	// =========================================================

	@GetMapping("/login/one-factor/password")
	public String oneFactorPasswordPage() {
		return "login/one-factor-password";
	}



	@PostMapping("/login/one-factor/password")
	public String oneFactorPasswordLogin(
			@RequestParam String username,
			@RequestParam String password,
			HttpServletRequest request,
			HttpServletResponse response,
			Model model) {

		Optional<User> optionalUser =
				userRepository.findByUsername(username);

		if (now_Lock) {
			model.addAttribute(
					"error",
					"アカウントが永久にロックされています。");
			return "login/one-factor-password";
		}

		if (optionalUser.isEmpty()) {

			model.addAttribute(
					"error",
					"ユーザー名またはパスワードが正しくありません");

			return "login/one-factor-password";
		}

		User user = optionalUser.get();

		if (!passwordEncoder.matches(
				password,
				user.getPassword())) {

			model.addAttribute(
					"error",
					"ユーザー名またはパスワードが正しくありません");

			if (Misslogin()) {//失敗回数カウントなど アカウント永久ロックでtrueを返す

				model.addAttribute(
						"error",
						"アカウントがロックされました。");
			}

			return "login/one-factor-password";
		}

		loginSuccess(user, request, response);

		return "redirect:/home";
	}



	// =========================================================
	// 一要素認証 - Email OTP
	// =========================================================

	@GetMapping("/login/one-factor/email")
	public String oneFactorEmailPage() {
		return "login/one-factor-email";
	}

	@PostMapping("/login/one-factor/email")
	public String oneFactorEmailLogin(
			@RequestParam String username,
			HttpSession session,
			Model model) {

		Optional<User> optionalUser =
				userRepository.findByUsername(username);

		if (optionalUser.isEmpty()) {

			model.addAttribute(
					"error",
					"ユーザー名が正しくありません");

			return "login/one-factor-email";
		}

		User user = optionalUser.get();

		if (user.getEmail() == null ||
				user.getEmail().isBlank()) {

			model.addAttribute(
					"error",
					"メールアドレスが登録されていません");

			return "login/one-factor-email";
		}

		String code =
				mailService.generateCode();

		verificationCodeService.saveCode(
				session,
				user.getEmail(),
				code);

		session.setAttribute(
				"oneFactorEmailUsername",
				user.getUsername());

		mailService.sendVerificationCode(
				user.getEmail(),
				code);

		return "redirect:/login/one-factor/email/code";
	}



	@GetMapping("/login/one-factor/email/code")
	public String oneFactorEmailCodePage(
			HttpSession session) {

		if (session.getAttribute(
				"oneFactorEmailUsername") == null) {

			return "redirect:/login/one-factor/email";
		}

		return "login/one-factor-email-code";
	}



	@PostMapping("/login/one-factor/email/code")
	public String verifyOneFactorEmailCode(
			@RequestParam String code,
			HttpSession session,
			HttpServletRequest request,
			HttpServletResponse response,
			Model model) {

		//答えを保存_なぎ
		String Answer =
				verificationCodeService.getCode(session);

		if (Answer == null) {

			model.addAttribute(
					"error",
					"認証コードが存在しません。もう一度ログインしてください");

			return "login/one-factor-email-code";
		}

		if (Answer.equals("時間切れ")) {

			model.addAttribute(
					"error",
					"認証コードの有効期限が切れています。もう一度ログインしてください");

			return "login/one-factor-email-code";
		}

		if (!verificationCodeService.verifyCode(
				session,
				code)) {

			model.addAttribute(
					"error",
					"認証コードが正しくありません");

			return "login/one-factor-email-code";
		}

		Object usernameObject =
				session.getAttribute(
						"oneFactorEmailUsername");

		if (usernameObject == null) {

			verificationCodeService.clearCode(session);

			return "redirect:/login/one-factor/email";
		}

		String username =
				usernameObject.toString();

		Optional<User> optionalUser =
				userRepository.findByUsername(username);

		if (optionalUser.isEmpty()) {

			verificationCodeService.clearCode(session);

			session.removeAttribute(
					"oneFactorEmailUsername");

			return "redirect:/login/one-factor/email";
		}

		User user = optionalUser.get();

		loginSuccess(user, request, response);

		verificationCodeService.clearCode(session);

		session.removeAttribute(
				"oneFactorEmailUsername");

		return "redirect:/home";
	}



	// =========================================================
	// 二要素認証
	// Password → Email OTP
	// =========================================================

	@GetMapping("/login/two-factor")
	public String twoFactorLogin() {
		return "login/two-factor-password";
	}



//	// =========================================================
//	// 二要素認証 第1段階 Password
//	// =========================================================
//
//	@GetMapping("/login/two-factor/password")
//	public String twoFactorPasswordPage() {
//		return "login/two-factor-password";
//	}
//
//
//
//	@PostMapping("/login/two-factor/password")
//	public String twoFactorPassword(
//			@RequestParam String username,
//			@RequestParam String password,
//			@RequestParam(
//					value = "fromAttackSimulator",
//					required = false)
//			String fromAttackSimulator,
//			HttpSession session,
//			Model model) {
//
//		Optional<User> optionalUser =
//				userRepository.findByUsername(username);
//
//		// =====================================================
//		// ユーザー確認
//		// =====================================================
//
//		if (optionalUser.isEmpty()) {
//
//			if ("true".equals(fromAttackSimulator)) {
//				return "LOGIN_FAILED";
//			}
//
//			model.addAttribute(
//					"error",
//					"ユーザー名またはパスワードが正しくありません");
//
//			return "login/two-factor-password";
//		}
//
//		User user = optionalUser.get();
//
//		// =====================================================
//		// Password確認
//		// =====================================================
//
//		if (now_Lock) {
//			model.addAttribute(
//					"error",
//					"アカウントが永久にロックされています。");
//			return "login/two-factor-password";
//		}
//
//		if (!passwordEncoder.matches(
//				password,
//				user.getPassword())) {
//
//			if ("true".equals(fromAttackSimulator)) {
//				return "LOGIN_FAILED";
//			}
//
//			model.addAttribute(
//					"error",
//					"ユーザー名またはパスワードが正しくありません");
//
//			if (Misslogin()) {//失敗回数カウントなど アカウント永久ロックでtrueを返す
//
//				model.addAttribute(
//						"error",
//						"アカウントがロックされました。");
//			}
//
//			return "login/two-factor-password";
//		}
//
//		// =====================================================
//		// メールアドレス確認
//		// =====================================================
//
//		if (user.getEmail() == null
//				|| user.getEmail().isBlank()) {
//
//			if ("true".equals(fromAttackSimulator)) {
//				return "EMAIL_NOT_FOUND";
//			}
//
//			model.addAttribute(
//					"error",
//					"メールアドレスが登録されていません");
//
//			return "login/two-factor-password";
//		}
//
//		// =====================================================
//		// 二要素認証Session
//		// =====================================================
//
//		session.setAttribute(
//				"twoFactorUsername",
//				user.getUsername());
//
//		// =====================================================
//		// AttackSimulatorからの場合
//		// =====================================================
//
//		if ("true".equals(fromAttackSimulator)) {
//
//			session.setAttribute(
//					"fromAttackSimulator",
//					true);
//
//			// -------------------------------------------------
//			// OTP生成
//			// -------------------------------------------------
//
//			String code =
//					mailService.generateCode();
//
//			// -------------------------------------------------
//			// OTP保存
//			// -------------------------------------------------
//
//			verificationCodeService.saveCode(
//					session,
//					user.getEmail(),
//					code);
//
//			// -------------------------------------------------
//			// OTP送信
//			// -------------------------------------------------
//
//			mailService.sendVerificationCode(
//					user.getEmail(),
//					code);
//
//			System.out.println(
//					"========================================");
//
//			System.out.println(
//					"AttackSimulator用二要素認証開始");
//
//			System.out.println(
//					"username = "
//							+ user.getUsername());
//
//			System.out.println(
//					"email = "
//							+ user.getEmail());
//
//			System.out.println(
//					"OTPを送信しました。");
//
//			System.out.println(
//					"========================================");
//
//			// =================================================
//			// ここが重要
//			//
//			// Thymeleaf画面ではなく、
//			// HTTPレスポンスとして文字列を返す
//			// =================================================
//
//			//return "redirect:/attack/otp-sent";
//			return "OTP_SENT";
//		}
//
//		// =====================================================
//		// 通常ログイン
//		// =====================================================
//
//		session.removeAttribute(
//				"fromAttackSimulator");
//
//		/*
//		 * 通常のブラウザ操作では、このメソッドに
//		 * @ResponseBodyを付けたため、
//		 * この分岐も文字列レスポンスになる。
//		 *
//		 * 通常ログイン画面は別の画面遷移を使うので、
//		 * 通常利用ではこのPOSTを直接使わない構成にする。
//		 */
//
//		return "redirect:/login/two-factor/email";
//		//return "OTP_SENT";
//	}
	
	// =========================================================
	// 二要素認証 第1段階 Password
	// =========================================================

	@GetMapping("/login/two-factor/password")
	public String twoFactorPasswordPage() {
		return "login/two-factor-password";
	}


	// =========================================================
	// 二要素認証 第1段階 Password
	// =========================================================

	@PostMapping("/login/two-factor/password")
	@ResponseBody
	public String twoFactorPassword(
			@RequestParam String username,
			@RequestParam String password,
			@RequestParam(
					value = "fromAttackSimulator",
					required = false)
			String fromAttackSimulator,
			HttpSession session,
			Model model) {

		Optional<User> optionalUser =
				userRepository.findByUsername(username);

		// =====================================================
		// ユーザー確認
		// =====================================================

		if (optionalUser.isEmpty()) {

			if ("true".equals(fromAttackSimulator)) {
				return "LOGIN_FAILED";
			}

			model.addAttribute(
					"error",
					"ユーザー名またはパスワードが正しくありません");

			return "login/two-factor-password";
		}

		User user = optionalUser.get();

		// =====================================================
		// Password確認
		// =====================================================

		if (now_Lock) {

			if ("true".equals(fromAttackSimulator)) {
				return "LOGIN_FAILED";
			}

			model.addAttribute(
					"error",
					"アカウントが永久にロックされています。");

			return "login/two-factor-password";
		}

		if (!passwordEncoder.matches(
				password,
				user.getPassword())) {

			if ("true".equals(fromAttackSimulator)) {
				return "LOGIN_FAILED";
			}

			model.addAttribute(
					"error",
					"ユーザー名またはパスワードが正しくありません");

			if (Misslogin()) {

				model.addAttribute(
						"error",
						"アカウントがロックされました。");
			}

			return "login/two-factor-password";
		}

		// =====================================================
		// メールアドレス確認
		// =====================================================

		if (user.getEmail() == null
				|| user.getEmail().isBlank()) {

			if ("true".equals(fromAttackSimulator)) {
				return "EMAIL_NOT_FOUND";
			}

			model.addAttribute(
					"error",
					"メールアドレスが登録されていません");

			return "login/two-factor-password";
		}

		// =====================================================
		// 二要素認証Session
		// =====================================================

		session.setAttribute(
				"twoFactorUsername",
				user.getUsername());

		// =====================================================
		// AttackSimulatorからの場合
		// =====================================================

		if ("true".equals(fromAttackSimulator)) {

			session.setAttribute(
					"fromAttackSimulator",
					true);

			// -------------------------------------------------
			// OTP生成
			// -------------------------------------------------

			String code =
					mailService.generateCode();

			// -------------------------------------------------
			// OTP保存
			// -------------------------------------------------

			verificationCodeService.saveCode(
					session,
					user.getEmail(),
					code);

			// -------------------------------------------------
			// OTP送信
			// -------------------------------------------------

			mailService.sendVerificationCode(
					user.getEmail(),
					code);

			System.out.println(
					"========================================");

			System.out.println(
					"AttackSimulator用二要素認証開始");

			System.out.println(
					"username = "
							+ user.getUsername());

			System.out.println(
					"email = "
							+ user.getEmail());

			System.out.println(
					"OTPを送信しました。");

			System.out.println(
					"========================================");

			// =================================================
			// AttackSimulatorには直接レスポンスを返す
			// =================================================

			return "OTP_SENT";
		}

		// =====================================================
		// 通常ログイン
		// =====================================================

		session.removeAttribute(
				"fromAttackSimulator");

		return "redirect:/login/two-factor/email";
	}

	@GetMapping("/attack/otp-sent")
	@ResponseBody
	public String attackOtpSent() {
		return "OTP_SENT";
	}



	// =========================================================
	// 二要素認証 第2段階 Email OTP送信
	// =========================================================

	@GetMapping("/login/two-factor/email")
	public String twoFactorEmailPage(
			HttpSession session) {

		if (session.getAttribute(
				"twoFactorUsername") == null) {

			return "redirect:/login/two-factor";
		}

		return "login/two-factor-email";
	}



	@PostMapping("/login/two-factor/email")
	public String twoFactorEmail(
			HttpSession session,
			Model model) {

		Object usernameObject =
				session.getAttribute("twoFactorUsername");

		if (usernameObject == null) {
			return "redirect:/login/two-factor";
		}

		String username =
				usernameObject.toString();

		Optional<User> optionalUser =
				userRepository.findByUsername(username);

		if (optionalUser.isEmpty()) {
			return "redirect:/login/two-factor";
		}

		User user = optionalUser.get();

		if (user.getEmail() == null ||
				user.getEmail().isBlank()) {

			model.addAttribute(
					"error",
					"メールアドレスが登録されていません");

			return "login/two-factor-email";
		}

		String code =
				mailService.generateCode();

		verificationCodeService.saveCode(
				session,
				user.getEmail(),
				code);

		mailService.sendVerificationCode(
				user.getEmail(),
				code);

		return "redirect:/login/two-factor/email/code";
	}



	// =========================================================
	// 二要素認証 第2段階 Email OTP入力
	// =========================================================

	@GetMapping("/login/two-factor/email/code")
	public String twoFactorEmailCodePage(
			HttpSession session) {

		if (session.getAttribute(
				"twoFactorUsername") == null) {

			return "redirect:/login/two-factor";
		}

		return "login/two-factor-email-code";
	}



	@PostMapping("/login/two-factor/email/code")
	public String verifyTwoFactorEmailCode(
			@RequestParam String code,
			HttpSession session,
			HttpServletRequest request,
			HttpServletResponse response,
			Model model) {

		if (verificationCodeService.getCode(session) == null) {

			model.addAttribute(
					"error",
					"認証コードの有効期限が切れています");

			return "login/two-factor-email-code";
		}

		if (!verificationCodeService.verifyCode(
				session,
				code)) {

			model.addAttribute(
					"error",
					"認証コードが正しくありません");

			return "login/two-factor-email-code";
		}

		Object usernameObject =
				session.getAttribute("twoFactorUsername");

		if (usernameObject == null) {

			verificationCodeService.clearCode(session);

			return "redirect:/login/two-factor";
		}

		String username =
				usernameObject.toString();

		Optional<User> optionalUser =
				userRepository.findByUsername(username);

		if (optionalUser.isEmpty()) {

			verificationCodeService.clearCode(session);

			session.removeAttribute(
					"twoFactorUsername");

			return "redirect:/login/two-factor";
		}

		User user = optionalUser.get();

		loginSuccess(user, request, response);

		verificationCodeService.clearCode(session);

		session.removeAttribute(
				"twoFactorUsername");

		return "redirect:/home";
	}



	// =========================================================
	// AttackSimulator用
	// 二要素認証 Email OTP確認
	// =========================================================

	@PostMapping("/login/two-factor/verify-otp")
	@ResponseBody
	public String verifyTwoFactorAttackOtp(
			@RequestParam String otp,
			HttpServletRequest request,
			HttpServletResponse response) {

		HttpSession session = request.getSession(false);

		if (session == null) {
			return "OTP_FAILED";
		}

		// =========================================
		// 二要素認証対象ユーザー取得
		// =========================================

		Object usernameObject =
				session.getAttribute("twoFactorUsername");

		if (usernameObject == null) {
			return "OTP_FAILED";
		}

		String username =
				usernameObject.toString();

		// =========================================
		// AttackSimulatorからの認証か確認
		// =========================================

		Object attackSimulatorObject =
				session.getAttribute("fromAttackSimulator");

		if (!Boolean.TRUE.equals(attackSimulatorObject)) {
			return "OTP_FAILED";
		}

		// =========================================
		// 保存されているOTPを取得
		// =========================================

		String savedCode =
				verificationCodeService.getCode(session);

		if (savedCode == null) {
			return "OTP_FAILED";
		}

		// =========================================
		// OTP確認
		// =========================================

		boolean verified =
				verificationCodeService.verifyCode(
						session,
						otp);

		if (!verified) {
			return "OTP_FAILED";
		}

		// =========================================
		// ログイン成功
		// =========================================

		Optional<User> optionalUser =
				userRepository.findByUsername(username);

		if (optionalUser.isEmpty()) {

			verificationCodeService.clearCode(session);

			session.removeAttribute(
					"twoFactorUsername");

			session.removeAttribute(
					"fromAttackSimulator");

			return "OTP_FAILED";
		}

		User user = optionalUser.get();

		loginSuccess(
				user,
				request,
				response);

		// =========================================
		// OTP・認証情報を削除
		// =========================================

		verificationCodeService.clearCode(session);

		session.removeAttribute(
				"twoFactorUsername");

		session.removeAttribute(
				"fromAttackSimulator");

		// =========================================
		// ホーム画面へ
		// =========================================

		return "LOGIN_SUCCESS";
	}



	// =========================================================
	// 通常の /login
	// =========================================================

	@GetMapping("/login")
	public String login() {
		return "redirect:/auth";
	}



	// =========================================================
	// 新規登録画面
	// =========================================================

	@GetMapping("/register")
	public String registerPage() {
		return "register";
	}



	// =========================================================
	// パスワード入力を失敗したときの処理　規定回数失敗したらロック
	// =========================================================

	private boolean Misslogin() {

		missloginCount++;//失敗回数をカウント

		if (missLimit <= missloginCount) {//失敗回数が一定数達したら

			if (penalty_Time.length > limitCount) {//範囲外対策
				limitCount++;//ペナルティレベルを上げる
			}

			if (penalty_Time[limitCount - 1] == -1) {//ペナルティ待機時間が-1なら永久ロック

				now_Lock = true;

				System.out.println(
						"アカウントが永久ロックされました");

				missloginCount = 0;//失敗回数をリセット

				return true;

			} else {

				System.out.println(
						penalty_Time[limitCount - 1]
								+ "秒待機してください");
			}

			missloginCount = 0;//失敗回数をリセット
		}

		return false;
	}



	// =========================================================
	// ユーザー登録
	// =========================================================

	@PostMapping("/register")
	public String registerUser(

			@RequestParam String username,

			@RequestParam String password,

			@RequestParam String password2,

			@RequestParam String password3,

			@RequestParam String email,

			Model model) {

		// ユーザー名重複確認

		if (userRepository.existsByUsername(username)) {

			model.addAttribute(
					"error",
					"そのユーザー名はすでに使用されています");

			return "register";
		}

		// ユーザー作成

		User user = new User();

		user.setUsername(username);

		user.setPassword(
				passwordEncoder.encode(password));

		user.setPassword2(
				passwordEncoder.encode(password2));

		user.setPassword3(
				passwordEncoder.encode(password3));

		user.setEmail(email);

		// DB保存

		userRepository.save(user);

		// 登録完了

		return "redirect:/auth";
	}



	// =========================================================
	// Google Authenticator登録画面
	// =========================================================

	// TOTP関連コードは現在無効化



	// =========================================================
	// Google Authenticator登録確認
	// =========================================================

	// TOTP関連コードは現在無効化



	// =========================================================
	// Google Authenticator確認画面
	// =========================================================

	// TOTP関連コードは現在無効化



	// =========================================================
	// TOTP QRコード
	// =========================================================

	// TOTP関連コードは現在無効化



	// =========================================================
	// ログイン成功処理
	// =========================================================

	private void loginSuccess(
			User user,
			HttpServletRequest request,
			HttpServletResponse response) {

		Authentication authentication =
				new UsernamePasswordAuthenticationToken(
						user.getUsername(),
						null,
						Collections.emptyList());

		SecurityContext context =
				SecurityContextHolder.createEmptyContext();

		context.setAuthentication(authentication);

		SecurityContextHolder.setContext(context);

		securityContextRepository.saveContext(
				context,
				request,
				response);
	}



	@PostMapping("/logout-from-attacksimulator")
	public String logoutFromAttackSimulator(
			HttpServletRequest request,
			HttpServletResponse response) {

		HttpSession session =
				request.getSession(false);

		if (session != null) {
			session.invalidate();
		}

		return "redirect:http://localhost:8081/result";
	}
}