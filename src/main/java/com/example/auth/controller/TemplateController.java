package com.example.auth.controller;

import com.example.auth.jwt.JwtTokenProvider;
import com.example.auth.jwt.UsernameAndPasswordAuthRequest;
import com.example.auth.jwt.entity.Token;
import com.example.auth.jwt.repository.TokenRepository;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import java.time.LocalDate;
import java.util.Date;
import java.util.List;
import java.util.UUID;

@Controller
public class TemplateController {

    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JwtTokenProvider jwtTokenProvider;
    @Autowired
    private TokenRepository tokenRepository;

    @PreAuthorize("hasRole('GUEST')")
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
        return "login";
    }
    @PostMapping("/app/login")
    public ResponseEntity<?> login(@RequestBody UsernameAndPasswordAuthRequest authRequest,
                                   HttpServletResponse response){
        try {
            // Authenticate user
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            authRequest.getUsername(),
                            authRequest.getPassword()
                    )
            );

            Date issueDate=new Date();
            Date expirationDate=java.sql.Date.valueOf(LocalDate.now().plusDays(1));
            String jti= UUID.randomUUID().toString();

            // Generate JWT
            String token = jwtTokenProvider.generateToken(issueDate,expirationDate,jti,authentication);

            // Invalidate old tokens
            tokenRepository.getTokenByEmail(authRequest.getUsername())
                    .ifPresent(this::invalidateOldTokens);

            // Save new token
            saveToken(authRequest.getUsername(), token,issueDate,expirationDate,jti);

            // Add token to cookie
            Cookie jwtCookie = new Cookie("token", token);
            jwtCookie.setHttpOnly(true);
            jwtCookie.setSecure(true);
            jwtCookie.setPath("/");
            jwtCookie.setMaxAge(86400); // 24 hours
            response.addCookie(jwtCookie);

            return ResponseEntity.ok("Login successful");
        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        }
    }

    @GetMapping("/app/logout")
    public String logout(HttpServletResponse response) {
        // Clear the "token" cookie by setting it with a zero max age
        Cookie tokenCookie = new Cookie("token", null);
        tokenCookie.setHttpOnly(true);
        tokenCookie.setSecure(true);
        tokenCookie.setPath("/");
        tokenCookie.setMaxAge(0); // Invalidate the cookie immediately
        response.addCookie(tokenCookie);

        // Redirect to the login page with a logout message
        return "redirect:/login?logout";
    }

    private void invalidateOldTokens(List<Token> oldTokens){
        try {
            for (Token token:oldTokens
            ) {
                token.setActive(false);
                tokenRepository.save(token);
            }
        }catch (Exception e){
            throw new RuntimeException("Could not invalidate tokens:" + oldTokens.toString());
        }
    }

    private void saveToken(String email, String token,Date issueDate,Date expirationDate,String jti) {
        Token newToken = new Token();
        newToken.setActive(true);
        newToken.setEmail(email);
        newToken.setCreatedAt(issueDate);
        newToken.setEndDate(expirationDate);
        newToken.setValue(token);
        newToken.setJti(jti);
        tokenRepository.save(newToken);
    }
}
