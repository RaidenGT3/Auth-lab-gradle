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
            .csrf(csrf -> csrf.disable())

            .authorizeHttpRequests(auth -> auth

                // =========================
                // 認証不要
                // =========================
                .requestMatchers(
                    "/",
                    "/auth",
                    "/auth/select",

                    // ログイン
                    "/login/**",

                    // =========================
                    // ユーザー登録
                    // =========================
                    "/register",
                    "/register/totp",
                    "/register/totp/verify",
                    "/register/totp/qr",

                    // CSS / JavaScript
                    "/css/**",
                    "/js/**"
                ).permitAll()

                // =========================
                // その他は認証必須
                // =========================
                .anyRequest().authenticated()
            )

            // =========================
            // ログアウト
            // =========================
            .logout(logout -> logout
                .logoutSuccessUrl("/auth")
                .permitAll()
            );

        return http.build();
    }
}