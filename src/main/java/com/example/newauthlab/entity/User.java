package com.example.newauthlab.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 50)
    private String username;

    @Column(nullable = false, length = 255)
    private String password;
    
    @Column(nullable = false, length = 255)
    private String password2;

    @Column(nullable = false, length = 255)
    private String password3;

    // メールアドレス
    @Column(nullable = false, unique = true, length = 255)
    private String email;

    // Google Authenticator用の秘密鍵
    @Column(length = 100)
    private String totpSecret;

    public Long getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }
    
    public String getPassword2() {
        return password2;
    }
    
    public String getPassword3() {
        return password3;
    }

    public void setPassword(String password) {
        this.password = password;
    }
    
    public void setPassword2(String password2) {
        this.password = password2;
    }
    
    public void setPassword3(String password3) {
        this.password = password3;
    }

    // =========================
    // email
    // =========================
    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    // =========================
    // TOTP
    // =========================
    public String getTotpSecret() {
        return totpSecret;
    }

    public void setTotpSecret(String totpSecret) {
        this.totpSecret = totpSecret;
    }
}