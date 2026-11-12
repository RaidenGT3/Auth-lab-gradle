
package com.example.newauthlab.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

	// =================================================
	// PasswordEncoder
	// =================================================
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	// =================================================
	// SecurityFilterChain
	// =================================================
	@Bean
	public SecurityFilterChain securityFilterChain(
			HttpSecurity http) throws Exception {

		http

		// =================================================
		// CSRF
		// =================================================
		.csrf(csrf -> csrf.disable())

		// =================================================
		// 認証・認可
		// =================================================
		.authorizeHttpRequests(auth -> auth

				// -------------------------------------------------
				// 認証不要
				// -------------------------------------------------
				.requestMatchers(

						// トップページ
						"/",

						// 認証方式選択
						"/auth",
						"/auth/select",

						// ログイン関連
						"/login/**",

						// ユーザー登録
						"/register",
						"/register/totp",
						"/register/totp/verify",
						"/register/totp/qr",

						// Email OTP
						"/email",
						"/otp",
						"/send-otp",
						"/verify-otp",
						"/success",

						// AttackSimulatorからのログイン引き継ぎ
						"/attack-login",

						// OTP有効期限確認
						"/attack/check-otp-expiration",

						// CSS
						"/css/**",

						// JavaScript
						"/js/**"

						).permitAll()

				// -------------------------------------------------
				// その他のページは認証必須
				// -------------------------------------------------
				.anyRequest().authenticated()
				)

		// =================================================
		// ログアウト
		// =================================================
		.logout(logout -> logout
				.logoutSuccessUrl("/auth")
				.permitAll()
				);

		return http.build();
	}
}
