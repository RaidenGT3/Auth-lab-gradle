package com.example.newauthlab.controller;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.example.newauthlab.entity.User;
import com.example.newauthlab.repository.UserRepository;

// 検証用ツールから送られてきたHTTPリクエストを受け取るController
@RestController
public class ExperimentController {


    		   // usersテーブルを操作するためのRepository
    	    private final UserRepository userRepository;

    	    // BCryptでハッシュ化されたパスワードと比較するために使用
    	    private final PasswordEncoder passwordEncoder;

    	    // UserRepositoryとPasswordEncoderを受け取る
    	    public ExperimentController(
    	            UserRepository userRepository,
    	            PasswordEncoder passwordEncoder) {

    	        this.userRepository = userRepository;
    	        this.passwordEncoder = passwordEncoder;
    	    }

    	    // 検証用ツールから送られてきた
    	    // usernameとpasswordを受け取る
    	    @PostMapping("/experiment/password")
    	    public String passwordTest(
    	            @RequestParam String username,
    	            @RequestParam String password) {

    	        // usernameからユーザーを検索
    	        User user = userRepository.findByUsername(username)
    	                .orElse(null);

    	        // ユーザーが存在しなければ認証失敗
    	        if (user == null) {
    	            return "FAILURE";
    	        }

    	        // 入力されたパスワードと
    	        // DBに保存されているパスワードハッシュを比較
    	        if (passwordEncoder.matches(
    	                password,
    	                user.getPassword1_hash())) {

    	            // 一致した場合
    	            return "成功";
    	        }

    	        // 一致しなかった場合
    	        return "失敗";
    	    }
    }
