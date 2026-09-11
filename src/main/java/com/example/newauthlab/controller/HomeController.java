package com.example.newauthlab.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {


//    @GetMapping("/")
//    public String home() {
//        return "auth-select";
//    }

    @GetMapping("/index")
    public String index() {
        return "index";
    }
}