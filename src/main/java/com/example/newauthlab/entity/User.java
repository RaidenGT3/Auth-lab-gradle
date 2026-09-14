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
    private String password1_hash;
    @Column(nullable = false, length = 255)
    private String password2_hash;
    @Column(nullable = false, length = 255)
    private String password3_hash;

    public Long getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword1_hash() {
        return password1_hash;
    }

    public void setPassword1_Hash(String password) {
        this.password1_hash = password;
    }
    
    public String getPassword2_hash() {
        return password2_hash;
    }

    public void setPassword2_Hash(String password) {
        this.password2_hash = password;
    }
    
    public String getPassword3_hash() {
        return password3_hash;
    }

    public void setPassword3_Hash(String password) {
        this.password3_hash = password;
    }
}