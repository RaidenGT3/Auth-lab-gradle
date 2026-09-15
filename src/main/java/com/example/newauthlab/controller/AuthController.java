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

import com.example.newauthlab.entity.User;
import com.example.newauthlab.repository.UserRepository;
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
    
    @GetMapping("/")
    public String root() {
        return "redirect:/auth";
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
            HttpServletRequest request,
            HttpServletResponse response,
            Model model) {

        Optional<User> optionalUser =
                userRepository.findByUsername(username);

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

            return "login/one-stage";
        }

        loginSuccess(user, request, response);

        return "redirect:/";
    }


    // =========================================================
    // 二段階認証
    // Password1 → Password2
    // =========================================================

    @GetMapping("/login/two-stage")
    public String twoStageLogin() {
        return "login/two-stage";
    }

    @PostMapping("/login/two-stage")
    public String twoStageLoginProcess(
            @RequestParam String username,
            @RequestParam String password,
            HttpSession session,
            Model model) {

        Optional<User> optionalUser =
                userRepository.findByUsername(username);

        if (optionalUser.isEmpty()) {

            model.addAttribute(
                    "error",
                    "ユーザー名またはパスワードが正しくありません");

            return "login/two-stage";
        }

        User user = optionalUser.get();

        // Password1
        if (!passwordEncoder.matches(
                password,
                user.getPassword())) {

            model.addAttribute(
                    "error",
                    "ユーザー名またはパスワードが正しくありません");

            return "login/two-stage";
        }

        // 1段階目成功
        session.setAttribute(
                "twoStageUsername",
                user.getUsername());

        return "redirect:/login/two-stage/password2";
    }


    // =========================================================
    // 二段階認証
    // Password2入力画面
    // =========================================================

    @GetMapping("/login/two-stage/password2")
    public String twoStagePassword2(
            HttpSession session) {

        if (session.getAttribute("twoStageUsername") == null) {
            return "redirect:/login/two-stage";
        }

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

        Object usernameObject =
                session.getAttribute("twoStageUsername");

        if (usernameObject == null) {
            return "redirect:/login/two-stage";
        }

        String username =
                usernameObject.toString();

        Optional<User> optionalUser =
                userRepository.findByUsername(username);

        if (optionalUser.isEmpty()) {

            session.removeAttribute("twoStageUsername");

            return "redirect:/login/two-stage";
        }

        User user = optionalUser.get();

        // Password2
        if (!passwordEncoder.matches(
                password2,
                user.getPassword2())) {

            model.addAttribute(
                    "error",
                    "Password2が正しくありません");

            return "login/two-stage-password2";
        }

        loginSuccess(user, request, response);

        session.removeAttribute("twoStageUsername");

        return "redirect:/";
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
    // 第1段階 Password1
    // =========================================================

    @PostMapping("/login/three-stage")
    public String threeStageLoginProcess(
            @RequestParam String username,
            @RequestParam String password,
            HttpSession session,
            Model model) {

        Optional<User> optionalUser =
                userRepository.findByUsername(username);

        if (optionalUser.isEmpty()) {

            model.addAttribute(
                    "error",
                    "ユーザー名またはパスワードが正しくありません");

            return "login/three-stage";
        }

        User user = optionalUser.get();

        if (!passwordEncoder.matches(
                password,
                user.getPassword())) {

            model.addAttribute(
                    "error",
                    "ユーザー名またはパスワードが正しくありません");

            return "login/three-stage";
        }

        session.setAttribute(
                "threeStageUsername",
                user.getUsername());

        return "redirect:/login/three-stage/password2";
    }


    // =========================================================
    // 三段階認証
    // 第2段階 Password2
    // =========================================================

    @GetMapping("/login/three-stage/password2")
    public String threeStagePassword2(
            HttpSession session) {

        if (session.getAttribute("threeStageUsername") == null) {
            return "redirect:/login/three-stage";
        }

        return "login/three-stage-password2";
    }


    @PostMapping("/login/three-stage/password2")
    public String verifyThreeStagePassword2(
            @RequestParam String password2,
            HttpSession session,
            Model model) {

        Object usernameObject =
                session.getAttribute("threeStageUsername");

        if (usernameObject == null) {
            return "redirect:/login/three-stage";
        }

        String username =
                usernameObject.toString();

        Optional<User> optionalUser =
                userRepository.findByUsername(username);

        if (optionalUser.isEmpty()) {
            session.removeAttribute("threeStageUsername");
            return "redirect:/login/three-stage";
        }

        User user = optionalUser.get();

        if (!passwordEncoder.matches(
                password2,
                user.getPassword2())) {

            model.addAttribute(
                    "error",
                    "Password2が正しくありません");

            return "login/three-stage-password2";
        }

        return "redirect:/login/three-stage/password3";
    }


    // =========================================================
    // 三段階認証
    // 第3段階 Password3
    // =========================================================

    @GetMapping("/login/three-stage/password3")
    public String threeStagePassword3(
            HttpSession session) {

        if (session.getAttribute("threeStageUsername") == null) {
            return "redirect:/login/three-stage";
        }

        return "login/three-stage-password3";
    }


    @PostMapping("/login/three-stage/password3")
    public String verifyThreeStagePassword3(
            @RequestParam String password3,
            HttpSession session,
            HttpServletRequest request,
            HttpServletResponse response,
            Model model) {

        Object usernameObject =
                session.getAttribute("threeStageUsername");

        if (usernameObject == null) {
            return "redirect:/login/three-stage";
        }

        String username =
                usernameObject.toString();

        Optional<User> optionalUser =
                userRepository.findByUsername(username);

        if (optionalUser.isEmpty()) {

            session.removeAttribute("threeStageUsername");

            return "redirect:/login/three-stage";
        }

        User user = optionalUser.get();

        if (!passwordEncoder.matches(
                password3,
                user.getPassword3())) {

            model.addAttribute(
                    "error",
                    "Password3が正しくありません");

            return "login/three-stage-password3";
        }

        loginSuccess(user, request, response);

        session.removeAttribute("threeStageUsername");

        return "redirect:/";
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

            return "login/one-factor-password";
        }

        loginSuccess(user, request, response);

        return "redirect:/";
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

        if (verificationCodeService.getCode(session) == null) {

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

        return "redirect:/";
    }


    // =========================================================
    // 二要素認証
    // Password → Email OTP
    // =========================================================

    @GetMapping("/login/two-factor")
    public String twoFactorLogin() {
        return "login/two-factor-password";
    }


    // =========================================================
    // 二要素認証 第1段階 Password
    // =========================================================

    @GetMapping("/login/two-factor/password")
    public String twoFactorPasswordPage() {
        return "login/two-factor-password";
    }


    @PostMapping("/login/two-factor/password")
    public String twoFactorPassword(
            @RequestParam String username,
            @RequestParam String password,
            HttpSession session,
            Model model) {

        Optional<User> optionalUser =
                userRepository.findByUsername(username);

        if (optionalUser.isEmpty()) {

            model.addAttribute(
                    "error",
                    "ユーザー名またはパスワードが正しくありません");

            return "login/two-factor-password";
        }

        User user = optionalUser.get();

        if (!passwordEncoder.matches(
                password,
                user.getPassword())) {

            model.addAttribute(
                    "error",
                    "ユーザー名またはパスワードが正しくありません");

            return "login/two-factor-password";
        }

        session.setAttribute(
                "twoFactorUsername",
                user.getUsername());

        return "redirect:/login/two-factor/email";
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

        return "redirect:/";
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
    // ユーザー登録
    // =========================================================

//    @PostMapping("/register")
//    public String registerUser(
//            @RequestParam String username,
//            @RequestParam String password,
//            @RequestParam String password2,
//            @RequestParam String password3,
//            @RequestParam String email,
//            HttpSession session,
//            Model model) {
//
//        // ユーザー名重複確認
//        if (userRepository.existsByUsername(username)) {
//
//            model.addAttribute(
//                    "error",
//                    "そのユーザー名はすでに使用されています");
//
//            return "register";
//        }
//
////        // メールアドレス重複確認
////        if (userRepository.existsByEmail(email)) {
////
////            model.addAttribute(
////                    "error",
////                    "そのメールアドレスはすでに使用されています");
////
////            return "register";
////        }
//
//        // ユーザー作成
//        User user = new User();
//
//        user.setUsername(username);
//
//        user.setPassword(
//                passwordEncoder.encode(password));
//
//        user.setPassword2(
//                passwordEncoder.encode(password2));
//
//        user.setPassword3(
//                passwordEncoder.encode(password3));
//
//        user.setEmail(email);
//
//        // TOTP秘密鍵生成
//        String secretKey =
//                totpService.generateSecretKey();
//
//        user.setTotpSecret(secretKey);
//
//        // DB保存
//        userRepository.save(user);
//
//        // TOTP登録用ユーザー名を保存
//        session.setAttribute(
//                "totpRegisterUsername",
//                username);
//
//        return "redirect:/register/totp";
//    }
    
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

//    @GetMapping("/register/totp")
//    public String registerTotp(
//            HttpSession session,
//            Model model) {
//
//        Object usernameObject =
//                session.getAttribute(
//                        "totpRegisterUsername");
//
//        if (usernameObject == null) {
//            return "redirect:/register";
//        }
//
//        String username =
//                usernameObject.toString();
//
//        Optional<User> optionalUser =
//                userRepository.findByUsername(username);
//
//        if (optionalUser.isEmpty()) {
//            return "redirect:/register";
//        }
//
//        User user = optionalUser.get();
//
//        String secretKey =
//                user.getTotpSecret();
//
//        String qrCodeUrl =
//                totpService.generateQrCodeUrl(
//                        "NewAuthLab",
//                        user.getUsername(),
//                        secretKey);
//
//        model.addAttribute(
//                "username",
//                user.getUsername());
//
//        model.addAttribute(
//                "secretKey",
//                secretKey);
//
//        model.addAttribute(
//                "qrCodeUrl",
//                qrCodeUrl);
//
//        return "register/totp";
//    }


    // =========================================================
    // Google Authenticator登録確認
    // =========================================================

//    @PostMapping("/register/totp/verify")
//    public String verifyRegisterTotp(
//            @RequestParam String code,
//            HttpSession session,
//            Model model) {
//
//        Object usernameObject =
//                session.getAttribute(
//                        "totpRegisterUsername");
//
//        if (usernameObject == null) {
//
//            model.addAttribute(
//                    "error",
//                    "登録情報が見つかりません。もう一度登録してください");
//
//            return "redirect:/register";
//        }
//
//        String username =
//                usernameObject.toString();
//
//        Optional<User> optionalUser =
//                userRepository.findByUsername(username);
//
//        if (optionalUser.isEmpty()) {
//
//            model.addAttribute(
//                    "error",
//                    "ユーザーが見つかりません");
//
//            return "redirect:/register";
//        }
//
//        User user = optionalUser.get();
//
//        int totpCode;
//
//        try {
//
//            totpCode =
//                    Integer.parseInt(code);
//
//        } catch (NumberFormatException e) {
//
//            model.addAttribute(
//                    "error",
//                    "認証コードは数字6桁で入力してください");
//
//            return "register-totp";
//        }
//
//        boolean verified =
//                totpService.verifyCode(
//                        user.getTotpSecret(),
//                        totpCode);
//
//        if (!verified) {
//
//            model.addAttribute(
//                    "error",
//                    "認証コードが正しくありません");
//
//            return "register-totp";
//        }
//
//        // TOTP登録完了
//        session.removeAttribute(
//                "totpRegisterUsername");
//
//        return "redirect:/auth";
//    }


    // =========================================================
    // Google Authenticator確認画面
    // =========================================================

//    @GetMapping("/register/totp/verify")
//    public String registerTotpVerifyPage() {
//        return "register-totp";
//    }


    // =========================================================
    // TOTP QRコード
    // =========================================================

//    @GetMapping("/register/totp/qr")
//    public ResponseEntity<byte[]> registerTotpQr(
//            HttpSession session) {
//
//        Object usernameObject =
//                session.getAttribute(
//                        "totpRegisterUsername");
//
//        if (usernameObject == null) {
//            return ResponseEntity.notFound().build();
//        }
//
//        String username =
//                usernameObject.toString();
//
//        Optional<User> optionalUser =
//                userRepository.findByUsername(username);
//
//        if (optionalUser.isEmpty()) {
//            return ResponseEntity.notFound().build();
//        }
//
//        User user = optionalUser.get();
//
//        String secretKey =
//                user.getTotpSecret();
//
//        if (secretKey == null ||
//                secretKey.isBlank()) {
//
//            return ResponseEntity.notFound().build();
//        }
//
//        String qrCodeUrl =
//                totpService.generateQrCodeUrl(
//                        "NewAuthLab",
//                        user.getUsername(),
//                        secretKey);
//
//        try {
//
//            byte[] qrCodeImage =
//                    qrCodeService.generateQrCode(
//                            qrCodeUrl,
//                            300,
//                            300);
//
//            return ResponseEntity
//                    .ok()
//                    .contentType(MediaType.IMAGE_PNG)
//                    .body(qrCodeImage);
//
//        } catch (WriterException | IOException e) {
//
//            return ResponseEntity
//                    .internalServerError()
//                    .build();
//        }
//    }


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
}