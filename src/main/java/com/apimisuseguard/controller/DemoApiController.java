package com.apimisuseguard.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DemoApiController {

    @GetMapping("/demo/home")
    public String home() {
        return "Normal API request allowed.";
    }

    @GetMapping("/demo/profile")
    public String profile() {
        return "Demo user profile data.";
    }

    @GetMapping("/demo/search")
    public String search() {
        return "Search request processed successfully.";
    }

    @GetMapping("/admin/users")
    public String adminUsers() {
        return "Protected admin user data.";
    }
}