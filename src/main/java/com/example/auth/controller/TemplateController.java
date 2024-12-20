package com.example.auth.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class TemplateController {
    @GetMapping("/home")
    public String getHomePage() {
        return "home";
    }

    @PreAuthorize("hasRole('USER')")
    @GetMapping("/user")
    public String getUserPage() {
        return "user";
    }
    @PreAuthorize("hasRole('GUEST')")
    @GetMapping("/guest")
    public String getGuestPage() {
        return "guest";
    }
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin")
    public String getAdminPage() {
        return "admin";
    }

    @GetMapping("/access-denied")
    public String accessDenied() {
        return "access-denied";
    }

    @GetMapping("/login")
    public String showLoginPage() {
        return "login"; // Returns the Thymeleaf template named "login.html"
    }
}
