package com.example.newauthlab.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http)
			throws Exception {

		http

				.authorizeHttpRequests(auth -> auth
						.requestMatchers(
								"/",
								"/auth",
								"/auth/select",
								"/login/one-factor",
								"/login/two-factor",
								"/login/three-factor",
								"/login",
								"/password",
								"/register",
								"/email",
								"/otp",
								"/send-otp",
								"/verify-otp")
						.permitAll()
						.anyRequest().authenticated())
				.formLogin(form -> form
						.loginPage("/login")
						.successHandler((request, response, authentication) -> {

							//セッションを取り出す　取り出したセッションにより２回目以降の認証を決定する
							String authState = (String) request.getSession()
									.getAttribute("authState");
							System.out.println("authState: " + authState);
							if (authState == null) {
								response.sendRedirect("/index");
								return;
							}
							switch (authState) {

							// =========================
							// 多段階認証
							// =========================
							case "two-stage":
								request.getSession().setAttribute(
								        "loginUsername",
								        authentication.getName()
								);
								response.sendRedirect("/password");
								break;
							case "three-stage-now-step1":
								request.getSession().setAttribute(
								        "loginUsername",
								        authentication.getName()
								);
								response.sendRedirect("/password");
								break;

							// =========================
							// 二要素認証
							// =========================
							// 知識 + 所有
							case "knowledge-possession":
								response.sendRedirect("/email");
								break;

							// 知識 + 生体
							case "knowledge-biometric":
								response.sendRedirect("/index");
								break;

							// 所有 + 生体の場合はEmailControllerで処理するためここでは処理しない

							// =========================
							// 三要素認証
							// =========================
							// 3要素認証 1回目（知識認証）成功後
							case "three-factor-now-step1":
								request.getSession().setAttribute(
										"authState",
										"three-factor-now-step2");

								response.sendRedirect("/email");
								break;

							// 3要素認証 2回目（所有認証）成功後 の処理はEmailControllerで行うためここでは処理しない
							//生体認証については完成次第考える
							case "three-factor-now-step3":
								response.sendRedirect("/index");
								break;

							default:

								//それ以外ならログイン成功がめんへ　
								response.sendRedirect("/index");
								break;
							}
						})
						.permitAll())

				.logout(logout -> logout
						.logoutSuccessUrl("/auth")
						.permitAll());

		return http.build();
	}
}