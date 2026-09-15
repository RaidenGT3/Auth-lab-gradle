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

    // =========================
    // ユーザー名
    // =========================
    @Column(nullable = false, unique = true, length = 50)
    private String username;

    // =========================
    // パスワード1
    // =========================
    @Column(nullable = false, length = 255)
    private String password;

    // =========================
    // パスワード2
    // =========================
    @Column(nullable = false, length = 255)
    private String password2;

    // =========================
    // パスワード3
    // =========================
    @Column(nullable = false, length = 255)
    private String password3;

    // =========================
    // メールアドレス
    // =========================
    @Column(nullable = false, length = 255)
    private String email;

    // =========================
    // ID
    // =========================
    public Long getId() {
        return id;
    }

    // =========================
    // username
    // =========================
    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    // =========================
    // password1
    // =========================
    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    // =========================
    // password2
    // =========================
    public String getPassword2() {
        return password2;
    }

    public void setPassword2(String password2) {
        this.password2 = password2;
    }

    // =========================
    // password3
    // =========================
    public String getPassword3() {
        return password3;
    }

    public void setPassword3(String password3) {
        this.password3 = password3;
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

}