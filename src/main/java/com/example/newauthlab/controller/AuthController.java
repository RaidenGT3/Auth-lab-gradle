package com.example.newauthlab.controller;

import java.io.IOException;
import java.util.Optional;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
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

import com.example.newauthlab.entity.User;
import com.example.newauthlab.repository.UserRepository;
import com.example.newauthlab.service.MailService;
import com.example.newauthlab.service.QrCodeService;
import com.example.newauthlab.service.TotpService;
import com.example.newauthlab.service.VerificationCodeService;
import com.google.zxing.WriterException;

@Controller
public class AuthController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final MailService mailService;
    private final VerificationCodeService verificationCodeService;
    private final TotpService totpService;
    private final QrCodeService qrCodeService;
    
    // Spring Securityのログイン状態をセッションに保存するために使用
    private final SecurityContextRepository securityContextRepository =
            new HttpSessionSecurityContextRepository();


    public AuthController(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            MailService mailService,
            VerificationCodeService verificationCodeService,
            TotpService totpService,
            QrCodeService qrCodeService) {

        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.mailService = mailService;
        this.verificationCodeService = verificationCodeService;
        this.totpService = totpService;
        this.qrCodeService = qrCodeService;
    }


    // =========================
    // 認証選択画面
    // =========================

    @GetMapping("/auth")
    public String authSelect() {
        return "auth-select";
    }


    // =========================
    // 認証方式選択処理
    // =========================

    @PostMapping("/auth/select")
    public String selectAuth(
            @RequestParam String authType) {

        switch (authType) {

            // 一段階認証
            case "one-stage":
                return "redirect:/login/one-stage";

            // 二段階認証
            case "two-stage":
                return "redirect:/login/two-stage";

            // 三段階認証
            case "three-stage":
                return "redirect:/login/three-stage";

            // 一要素認証
            case "one-factor":
                return "redirect:/login/one-factor";

            // 二要素認証
            case "two-factor":
                return "redirect:/login/two-factor";

            // 三要素認証
            case "three-factor":
                return "redirect:/login/three-factor";

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
        return "login/one-stage";
    }


    // =========================
    // 一段階認証
    // ユーザー名・パスワード確認
    // =========================

    @PostMapping("/login/one-stage")
    public String oneStageLoginProcess(
            @RequestParam String username,
            @RequestParam String password,
            HttpServletRequest request,
            HttpServletResponse response,
            Model model) {

        // =========================
        // ユーザーを検索
        // =========================

        Optional<User> optionalUser =
                userRepository.findByUsername(username);

        // ユーザーが存在しない場合
        if (optionalUser.isEmpty()) {

            model.addAttribute(
                    "error",
                    "ユーザー名またはパスワードが正しくありません"
            );

            return "login/one-stage";
        }


        // ユーザーを取得
        User user = optionalUser.get();


        // =========================
        // パスワードを確認
        // =========================

        if (!passwordEncoder.matches(
                password,
                user.getPassword())) {

            model.addAttribute(
                    "error",
                    "ユーザー名またはパスワードが正しくありません"
            );

            return "login/one-stage";
        }


        // =========================
        // Spring Securityにログイン情報を設定
        // =========================

        Authentication authentication =
                new UsernamePasswordAuthenticationToken(
                        user.getUsername(),
                        null,
                        java.util.Collections.emptyList()
                );


        SecurityContext context =
                SecurityContextHolder.createEmptyContext();

        context.setAuthentication(authentication);

        SecurityContextHolder.setContext(context);


        // =========================
        // ログイン状態をセッションに保存
        // =========================

        securityContextRepository.saveContext(
                context,
                request,
                response
        );


        // =========================
        // ログイン成功
        // =========================

        return "redirect:/";
    }


    // =========================
    // 二段階認証ログイン画面
    // =========================

    @GetMapping("/login/two-stage")
    public String twoStageLogin() {
        return "login/two-stage";
    }


    // =========================
    // 二段階認証
    // ユーザー名・パスワード確認
    // =========================

    @PostMapping("/login/two-stage")
    public String twoStageLoginProcess(
            @RequestParam String username,
            @RequestParam String password,
            HttpSession session,
            Model model) {

        // =========================
        // ユーザーを検索
        // =========================

        Optional<User> optionalUser =
                userRepository.findByUsername(username);

        // ユーザーが存在しない場合
        if (optionalUser.isEmpty()) {

            model.addAttribute(
                    "error",
                    "ユーザー名またはパスワードが正しくありません"
            );

            return "login/two-stage";
        }


        // ユーザーを取得
        User user = optionalUser.get();


        // =========================
        // パスワードを確認
        // =========================

        if (!passwordEncoder.matches(
                password,
                user.getPassword())) {

            model.addAttribute(
                    "error",
                    "ユーザー名またはパスワードが正しくありません"
            );

            return "login/two-stage";
        }


        // =========================
        // メールアドレスが登録されているか確認
        // =========================

        if (user.getEmail() == null ||
                user.getEmail().isBlank()) {

            model.addAttribute(
                    "error",
                    "メールアドレスが登録されていません"
            );

            return "login/two-stage";
        }


        // =========================
        // 認証コードを生成
        // =========================

        String code =
                mailService.generateCode();


        // =========================
        // 認証コードをセッションに保存
        // =========================

        verificationCodeService.saveCode(
                session,
                user.getEmail(),
                code
        );


        // =========================
        // 二段階認証で使用するユーザー名を保存
        // =========================

        session.setAttribute(
                "twoStageUsername",
                user.getUsername()
        );


        // =========================
        // 認証コードをメール送信
        // =========================

        mailService.sendVerificationCode(
                user.getEmail(),
                code
        );


        // =========================
        // 認証コード入力画面へ
        // =========================

        return "redirect:/login/two-stage/code";
    }


    // =========================
    // 二段階認証
    // 認証コード入力画面
    // =========================

    @GetMapping("/login/two-stage/code")
    public String twoStageCode(
            HttpSession session) {

        // 認証コードが存在しない場合は
        // 二段階認証の最初の画面へ戻す
        if (verificationCodeService.getCode(session) == null) {
            return "redirect:/login/two-stage";
        }

        return "login/two-stage-code";
    }


    // =========================
    // 二段階認証
    // 認証コード確認処理
    // =========================

    @PostMapping("/login/two-stage/code")
    public String verifyTwoStageCode(
            @RequestParam String code,
            HttpSession session,
            HttpServletRequest request,
            HttpServletResponse response,
            Model model) {

        // =========================
        // 認証コードが存在するか確認
        // =========================

        String savedCode =
                verificationCodeService.getCode(session);

        if (savedCode == null) {

            model.addAttribute(
                    "error",
                    "認証コードの有効期限が切れています。もう一度ログインしてください"
            );

            return "login/two-stage-code";
        }


        // =========================
        // 認証コードを確認
        // =========================

        if (!verificationCodeService.verifyCode(
                session,
                code)) {

            model.addAttribute(
                    "error",
                    "認証コードが正しくありません"
            );

            return "login/two-stage-code";
        }


        // =========================
        // ユーザー名をセッションから取得
        // =========================

        Object usernameObject =
                session.getAttribute("twoStageUsername");

        if (usernameObject == null) {

            model.addAttribute(
                    "error",
                    "認証情報が確認できません。もう一度ログインしてください"
            );

            verificationCodeService.clearCode(session);

            return "login/two-stage";
        }

        String username =
                usernameObject.toString();


        // =========================
        // ユーザーを取得
        // =========================

        Optional<User> optionalUser =
                userRepository.findByUsername(username);

        if (optionalUser.isEmpty()) {

            model.addAttribute(
                    "error",
                    "ユーザーが見つかりません"
            );

            verificationCodeService.clearCode(session);

            return "login/two-stage";
        }

        User user = optionalUser.get();


        // =========================
        // Spring Securityにログイン情報を設定
        // =========================

        Authentication authentication =
                new UsernamePasswordAuthenticationToken(
                        user.getUsername(),
                        null,
                        java.util.Collections.emptyList()
                );


        SecurityContext context =
                SecurityContextHolder.createEmptyContext();

        context.setAuthentication(authentication);

        SecurityContextHolder.setContext(context);


        // =========================
        // ログイン状態をセッションに保存
        // =========================

        securityContextRepository.saveContext(
                context,
                request,
                response
        );


        // =========================
        // 使用済み認証コードを削除
        // =========================

        verificationCodeService.clearCode(session);


        // =========================
        // 二段階認証用のユーザー名も削除
        // =========================

        session.removeAttribute("twoStageUsername");


        // =========================
        // ログイン成功
        // =========================

        return "redirect:/";
    }


    // =========================
    // 三段階認証ログイン画面
    // =========================

    @GetMapping("/login/three-stage")
    public String threeStageLogin() {
        return "login/three-stage";
    }
    
	 // =========================
	 // 三段階認証
	 // ① ユーザー名・パスワード確認
	 // =========================
	
	 @PostMapping("/login/three-stage")
	 public String threeStageLoginProcess(
	         @RequestParam String username,
	         @RequestParam String password,
	         HttpSession session,
	         Model model) {
	
	     // =========================
	     // ユーザーを検索
	     // =========================
	
	     Optional<User> optionalUser =
	             userRepository.findByUsername(username);
	
	     if (optionalUser.isEmpty()) {
	
	         model.addAttribute(
	                 "error",
	                 "ユーザー名またはパスワードが正しくありません"
	         );
	
	         return "login/three-stage";
	     }
	
	     User user = optionalUser.get();
	
	
	     // =========================
	     // パスワードを確認
	     // =========================
	
	     if (!passwordEncoder.matches(
	             password,
	             user.getPassword())) {
	
	         model.addAttribute(
	                 "error",
	                 "ユーザー名またはパスワードが正しくありません"
	         );
	
	         return "login/three-stage";
	     }
	
	
	     // =========================
	     // メールアドレスを確認
	     // =========================
	
	     if (user.getEmail() == null ||
	             user.getEmail().isBlank()) {
	
	         model.addAttribute(
	                 "error",
	                 "メールアドレスが登録されていません"
	         );
	
	         return "login/three-stage";
	     }
	
	
	     // =========================
	     // TOTPが登録されているか確認
	     // =========================
	
	     if (user.getTotpSecret() == null ||
	             user.getTotpSecret().isBlank()) {
	
	         model.addAttribute(
	                 "error",
	                 "Google Authenticatorが登録されていません"
	         );
	
	         return "login/three-stage";
	     }
	
	
	     // =========================
	     // メール認証コードを生成
	     // =========================
	
	     String code =
	             mailService.generateCode();
	
	
	     // =========================
	     // 認証コードを保存
	     // =========================
	
	     verificationCodeService.saveCode(
	             session,
	             user.getEmail(),
	             code
	     );
	
	
	     // =========================
	     // 三段階認証用ユーザー名を保存
	     // =========================
	
	     session.setAttribute(
	             "threeStageUsername",
	             user.getUsername()
	     );
	
	
	     // =========================
	     // メール送信
	     // =========================
	
	     mailService.sendVerificationCode(
	             user.getEmail(),
	             code
	     );
	
	
	     // =========================
	     // メール認証画面へ
	     // =========================
	
	     return "redirect:/login/three-stage/code";
	 }
	 
	// =========================
	// 三段階認証
	// ② メール認証コード入力画面
	// =========================

	@GetMapping("/login/three-stage/code")
	public String threeStageCode(
	        HttpSession session) {

	    if (verificationCodeService.getCode(session) == null) {
	        return "redirect:/login/three-stage";
	    }

	    return "login/three-stage-code";
	}

	// =========================
	// 三段階認証
	// ② メール認証コード確認
	// =========================

	@PostMapping("/login/three-stage/code")
	public String verifyThreeStageCode(
	        @RequestParam String code,
	        HttpSession session,
	        Model model) {

	    // =========================
	    // 認証コードが存在するか確認
	    // =========================

	    String savedCode =
	            verificationCodeService.getCode(session);

	    if (savedCode == null) {

	        model.addAttribute(
	                "error",
	                "認証コードの有効期限が切れています。もう一度ログインしてください"
	        );

	        return "login/three-stage-code";
	    }


	    // =========================
	    // 認証コードを確認
	    // =========================

	    if (!verificationCodeService.verifyCode(
	            session,
	            code)) {

	        model.addAttribute(
	                "error",
	                "認証コードが正しくありません"
	        );

	        return "login/three-stage-code";
	    }


	    // =========================
	    // ユーザー名を取得
	    // =========================

	    Object usernameObject =
	            session.getAttribute("threeStageUsername");

	    if (usernameObject == null) {

	        verificationCodeService.clearCode(session);

	        return "redirect:/login/three-stage";
	    }


	    String username =
	            usernameObject.toString();


	    // =========================
	    // ユーザーを取得
	    // =========================

	    Optional<User> optionalUser =
	            userRepository.findByUsername(username);

	    if (optionalUser.isEmpty()) {

	        verificationCodeService.clearCode(session);

	        session.removeAttribute(
	                "threeStageUsername"
	        );

	        return "redirect:/login/three-stage";
	    }


	    User user = optionalUser.get();


	    // =========================
	    // TOTP登録を確認
	    // =========================

	    if (user.getTotpSecret() == null ||
	            user.getTotpSecret().isBlank()) {

	        model.addAttribute(
	                "error",
	                "Google Authenticatorが登録されていません"
	        );

	        return "login/three-stage-code";
	    }


	    // =========================
	    // メール認証完了
	    // =========================

	    verificationCodeService.clearCode(session);


	    // =========================
	    // TOTP認証画面へ
	    // =========================

	    return "redirect:/login/three-stage/totp";
	}
	
	// =========================
	// 三段階認証
	// ③ Google Authenticator入力画面
	// =========================

	@GetMapping("/login/three-stage/totp")
	public String threeStageTotp(
	        HttpSession session) {

	    Object usernameObject =
	            session.getAttribute("threeStageUsername");

	    if (usernameObject == null) {
	        return "redirect:/login/three-stage";
	    }

	    return "login/three-stage-totp";
	}
	
	// =========================
	// 三段階認証
	// ③ Google Authenticator確認
	// =========================

	@PostMapping("/login/three-stage/totp")
	public String verifyThreeStageTotp(
	        @RequestParam int code,
	        HttpSession session,
	        HttpServletRequest request,
	        HttpServletResponse response,
	        Model model) {

	    // =========================
	    // ユーザー名を取得
	    // =========================

	    Object usernameObject =
	            session.getAttribute("threeStageUsername");

	    if (usernameObject == null) {

	        return "redirect:/login/three-stage";
	    }


	    String username =
	            usernameObject.toString();


	    // =========================
	    // ユーザーを取得
	    // =========================

	    Optional<User> optionalUser =
	            userRepository.findByUsername(username);

	    if (optionalUser.isEmpty()) {

	        session.removeAttribute(
	                "threeStageUsername"
	        );

	        return "redirect:/login/three-stage";
	    }


	    User user = optionalUser.get();


	    // =========================
	    // TOTP秘密鍵を確認
	    // =========================

	    String secretKey =
	            user.getTotpSecret();

	    if (secretKey == null ||
	            secretKey.isBlank()) {

	        model.addAttribute(
	                "error",
	                "Google Authenticatorが登録されていません"
	        );

	        return "login/three-stage-totp";
	    }


	    // =========================
	    // Google Authenticatorコード確認
	    // =========================

	    boolean verified =
	            totpService.verifyCode(
	                    secretKey,
	                    code
	            );


	    if (!verified) {

	        model.addAttribute(
	                "error",
	                "認証コードが正しくありません"
	        );

	        return "login/three-stage-totp";
	    }


	    // =========================
	    // 3段階すべて成功
	    // =========================

	    Authentication authentication =
	            new UsernamePasswordAuthenticationToken(
	                    user.getUsername(),
	                    null,
	                    java.util.Collections.emptyList()
	            );


	    SecurityContext context =
	            SecurityContextHolder.createEmptyContext();

	    context.setAuthentication(authentication);

	    SecurityContextHolder.setContext(context);


	    // =========================
	    // ログイン状態をセッションに保存
	    // =========================

	    securityContextRepository.saveContext(
	            context,
	            request,
	            response
	    );


	    // =========================
	    // 三段階認証用セッションを削除
	    // =========================

	    session.removeAttribute(
	            "threeStageUsername"
	    );


	    // =========================
	    // ログイン成功
	    // =========================

	    return "redirect:/";
	}

    // =========================
    // 一要素認証ログイン画面
    // =========================

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

            case "passkey":
                return "redirect:/login/one-factor/passkey";

            default:
                return "redirect:/login/one-factor";
        }
    }
    
	 // =========================
	 // 一要素認証 - Password認証
	 // =========================
	
	 @PostMapping("/login/one-factor/password")
	 public String oneFactorPasswordLogin(
	         @RequestParam String username,
	         @RequestParam String password,
	         HttpServletRequest request,
	         HttpServletResponse response,
	         Model model) {
	
	     Optional<User> optionalUser =
	             userRepository.findByUsername(username);
	
	     // ユーザーが存在しない
	     if (optionalUser.isEmpty()) {
	
	         model.addAttribute(
	                 "error",
	                 "ユーザー名またはパスワードが正しくありません"
	         );
	
	         return "login/one-factor-password";
	     }
	
	     User user = optionalUser.get();
	
	     // パスワード確認
	     if (!passwordEncoder.matches(
	             password,
	             user.getPassword())) {
	
	         model.addAttribute(
	                 "error",
	                 "ユーザー名またはパスワードが正しくありません"
	         );
	
	         return "login/one-factor-password";
	     }
	
	     // =========================
	     // 認証成功
	     // =========================
	
	     Authentication authentication =
	             new UsernamePasswordAuthenticationToken(
	                     user.getUsername(),
	                     null,
	                     java.util.Collections.emptyList()
	             );
	
	     SecurityContext context =
	             SecurityContextHolder.createEmptyContext();
	
	     context.setAuthentication(authentication);
	
	     SecurityContextHolder.setContext(context);
	
	     securityContextRepository.saveContext(
	             context,
	             request,
	             response
	     );
	
	     return "redirect:/";
	 }
	 
	// =========================
	// 一要素認証 - Email OTP送信
	// =========================

	@PostMapping("/login/one-factor/email")
	public String oneFactorEmailLogin(
	        @RequestParam String username,
	        HttpSession session,
	        Model model) {

	    Optional<User> optionalUser =
	            userRepository.findByUsername(username);

	    // ユーザーが存在しない
	    if (optionalUser.isEmpty()) {

	        model.addAttribute(
	                "error",
	                "ユーザー名が正しくありません"
	        );

	        return "login/one-factor-email";
	    }

	    User user = optionalUser.get();

	    // メールアドレスが登録されていない
	    if (user.getEmail() == null ||
	            user.getEmail().isBlank()) {

	        model.addAttribute(
	                "error",
	                "メールアドレスが登録されていません"
	        );

	        return "login/one-factor-email";
	    }

	    // 6桁の認証コードを生成
	    String code =
	            mailService.generateCode();

	    // セッションに保存
	    verificationCodeService.saveCode(
	            session,
	            user.getEmail(),
	            code
	    );

	    // 一要素認証用のユーザー名を保存
	    session.setAttribute(
	            "oneFactorEmailUsername",
	            user.getUsername()
	    );

	    // メール送信
	    mailService.sendVerificationCode(
	            user.getEmail(),
	            code
	    );

	    return "redirect:/login/one-factor/email/code";
	}
	
	// =========================
	// 一要素認証 - Email OTP検証
	// =========================

	@PostMapping("/login/one-factor/email/code")
	public String verifyOneFactorEmailCode(
	        @RequestParam String code,
	        HttpSession session,
	        HttpServletRequest request,
	        HttpServletResponse response,
	        Model model) {

	    // 保存されている認証コードを確認
	    String savedCode =
	            verificationCodeService.getCode(session);

	    if (savedCode == null) {

	        model.addAttribute(
	                "error",
	                "認証コードの有効期限が切れています。もう一度ログインしてください"
	        );

	        return "login/one-factor-email-code";
	    }

	    // 認証コードを検証
	    if (!verificationCodeService.verifyCode(
	            session,
	            code)) {

	        model.addAttribute(
	                "error",
	                "認証コードが正しくありません"
	        );

	        return "login/one-factor-email-code";
	    }

	    // 一要素認証用のユーザー名を取得
	    Object usernameObject =
	            session.getAttribute(
	                    "oneFactorEmailUsername"
	            );

	    if (usernameObject == null) {

	        verificationCodeService.clearCode(session);

	        return "redirect:/login/one-factor/email";
	    }

	    String username =
	            usernameObject.toString();

	    // ユーザーをDBから取得
	    Optional<User> optionalUser =
	            userRepository.findByUsername(username);

	    if (optionalUser.isEmpty()) {

	        verificationCodeService.clearCode(session);

	        session.removeAttribute(
	                "oneFactorEmailUsername"
	        );

	        return "redirect:/login/one-factor/email";
	    }

	    User user = optionalUser.get();

	    // =========================
	    // 認証成功
	    // =========================

	    Authentication authentication =
	            new UsernamePasswordAuthenticationToken(
	                    user.getUsername(),
	                    null,
	                    java.util.Collections.emptyList()
	            );

	    SecurityContext context =
	            SecurityContextHolder.createEmptyContext();

	    context.setAuthentication(authentication);

	    SecurityContextHolder.setContext(context);

	    securityContextRepository.saveContext(
	            context,
	            request,
	            response
	    );

	    // 認証コードと一時情報を削除
	    verificationCodeService.clearCode(session);

	    session.removeAttribute(
	            "oneFactorEmailUsername"
	    );

	    return "redirect:/";
	}
	
	// =========================
	// Passkey登録画面
	// =========================

	@GetMapping("/register/passkey")
	public String registerPasskey() {
	    return "register-passkey";
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
        return "redirect:/auth";
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
            @RequestParam String password,
            @RequestParam String email,
            HttpSession session,
            Model model) {

        // =========================
        // ユーザー名がすでに存在するか確認
        // =========================

        if (userRepository.existsByUsername(username)) {

            model.addAttribute(
                    "error",
                    "そのユーザー名はすでに使用されています"
            );

            return "register";
        }


        // =========================
        // 新しいユーザーを作成
        // =========================

        User user = new User();

        user.setUsername(username);


        // パスワードをBCryptで暗号化
        user.setPassword(
                passwordEncoder.encode(password)
        );


        // メールアドレスを保存
        user.setEmail(email);


        // =========================
        // Google Authenticator用秘密鍵を生成
        // =========================

        String secretKey =
                totpService.generateSecretKey();

        user.setTotpSecret(secretKey);


        // =========================
        // データベースへ保存
        // =========================

        userRepository.save(user);


        // =========================
        // TOTP登録に必要な情報をセッションへ保存
        // =========================

        session.setAttribute(
                "totpRegisterUsername",
                username
        );


        // =========================
        // Google Authenticator設定画面へ
        // =========================

        return "redirect:/register/totp";
    }
    
	 // =========================
	 // Google Authenticator登録画面
	 // =========================
	
	 @GetMapping("/register/totp")
	 public String registerTotp(
	         HttpSession session,
	         Model model) {
	
	     Object usernameObject =
	             session.getAttribute("totpRegisterUsername");
	
	     if (usernameObject == null) {
	         return "redirect:/register";
	     }
	
	     String username =
	             usernameObject.toString();
	
	     Optional<User> optionalUser =
	             userRepository.findByUsername(username);
	
	     if (optionalUser.isEmpty()) {
	         return "redirect:/register";
	     }
	
	     User user = optionalUser.get();
	
	     String secretKey =
	             user.getTotpSecret();
	
	     String qrCodeUrl =
	             totpService.generateQrCodeUrl(
	                     "NewAuthLab",
	                     user.getUsername(),
	                     secretKey
	             );
	
	     model.addAttribute(
	             "username",
	             user.getUsername()
	     );
	
	     model.addAttribute(
	             "secretKey",
	             secretKey
	     );
	
	     model.addAttribute(
	             "qrCodeUrl",
	             qrCodeUrl
	     );
	
	     return "register/totp";
	 }
	 
	// =========================
	// Google Authenticator登録確認
	// =========================

	 
	 @PostMapping("/register/totp/verify")
	 public String verifyRegisterTotp(
	         @RequestParam String code,
	         HttpSession session,
	         HttpServletRequest request,
	         HttpServletResponse response,
	         Model model) {

	     Object usernameObject =
	             session.getAttribute("totpRegisterUsername");

	     if (usernameObject == null) {

	         model.addAttribute(
	                 "error",
	                 "登録情報が見つかりません。もう一度登録してください"
	         );

	         return "redirect:/register";
	     }

	     String username =
	             usernameObject.toString();

	     Optional<User> optionalUser =
	             userRepository.findByUsername(username);

	     if (optionalUser.isEmpty()) {

	         model.addAttribute(
	                 "error",
	                 "ユーザーが見つかりません"
	         );

	         return "redirect:/register";
	     }

	     User user =
	             optionalUser.get();

	     String codeString =
	             String.valueOf(code);

	     int totpCode;

	     try {

	         totpCode =
	                 Integer.parseInt(codeString);

	     } catch (NumberFormatException e) {

	         model.addAttribute(
	                 "error",
	                 "認証コードは数字6桁で入力してください"
	         );

	         return "register-totp";
	     }

	     boolean verified =
	             totpService.verifyCode(
	                     user.getTotpSecret(),
	                     totpCode
	             );

	     if (!verified) {

	         model.addAttribute(
	                 "error",
	                 "認証コードが正しくありません"
	         );

	         return "register-totp";
	     }


	     /*
	      * TOTP認証成功
	      *
	      * Passkey登録では、
	      * Spring Securityが「現在認証されているユーザー」
	      * を必要とするため、ここで一時的に認証状態にする。
	      */

	     Authentication authentication =
	             new UsernamePasswordAuthenticationToken(
	                     user.getUsername(),
	                     null,
	                     java.util.Collections.emptyList()
	             );

	     SecurityContext context =
	             SecurityContextHolder.createEmptyContext();

	     context.setAuthentication(authentication);

	     SecurityContextHolder.setContext(context);

	     securityContextRepository.saveContext(
	             context,
	             request,
	             response
	     );


	     /*
	      * Passkey登録用の一時セッション情報
	      */
	     session.setAttribute(
	             "passkeyRegisterUsername",
	             user.getUsername()
	     );

	     session.removeAttribute(
	             "totpRegisterUsername"
	     );


	     /*
	      * Passkey登録画面へ
	      */
	     return "redirect:/register/passkey";
	 }

	
	// =========================
	// Google Authenticator
	// QRコード画像
	// =========================

	@GetMapping("/register/totp/qr")
	public ResponseEntity<byte[]> registerTotpQr(
	        HttpSession session) {

	    Object usernameObject =
	            session.getAttribute("totpRegisterUsername");

	    if (usernameObject == null) {
	        return ResponseEntity.notFound().build();
	    }

	    String username =
	            usernameObject.toString();

	    Optional<User> optionalUser =
	            userRepository.findByUsername(username);

	    if (optionalUser.isEmpty()) {
	        return ResponseEntity.notFound().build();
	    }

	    User user = optionalUser.get();

	    String secretKey =
	            user.getTotpSecret();

	    if (secretKey == null ||
	            secretKey.isBlank()) {

	        return ResponseEntity.notFound().build();
	    }


	    // =========================
	    // Google Authenticator用URL
	    // =========================

	    String qrCodeUrl =
	            totpService.generateQrCodeUrl(
	                    "NewAuthLab",
	                    user.getUsername(),
	                    secretKey
	            );


	    try {

	        byte[] qrCodeImage =
	                qrCodeService.generateQrCode(
	                        qrCodeUrl,
	                        300,
	                        300
	                );

	        return ResponseEntity
	                .ok()
	                .contentType(MediaType.IMAGE_PNG)
	                .body(qrCodeImage);

	    } catch (WriterException | IOException e) {

	        return ResponseEntity
	                .internalServerError()
	                .build();
	    }
	}
}