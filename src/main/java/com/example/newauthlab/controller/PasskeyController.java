package com.example.newauthlab.controller;

import jakarta.servlet.http.HttpSession;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import com.example.newauthlab.entity.User;
import com.example.newauthlab.repository.UserRepository;

@Controller
public class PasskeyController {

    private final UserRepository userRepository;

    public PasskeyController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @GetMapping("/register/passkey")
    public String registerPasskey(
            HttpSession session,
            Model model) {

        Object usernameObject =
                session.getAttribute("passkeyRegisterUsername");

        if (usernameObject == null) {
            return "redirect:/register";
        }

        String username =
                usernameObject.toString();

        User user = userRepository
                .findByUsername(username)
                .orElse(null);

        if (user == null) {
            return "redirect:/register";
        }

        model.addAttribute(
                "username",
                user.getUsername()
        );

        return "register-passkey";
    }
}