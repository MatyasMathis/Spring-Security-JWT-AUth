package com.example.auth.jwt;

import com.example.auth.jwt.entity.Token;
import com.example.auth.jwt.repository.TokenRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.LocalDate;
import java.util.*;

public class JwtUsernameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;
    private TokenRepository tokenRepository;

    public JwtUsernameAndPasswordAuthenticationFilter(AuthenticationManager authenticationManager,TokenRepository tokenRepository) {
        this.authenticationManager = authenticationManager;
        this.tokenRepository=tokenRepository;
    }
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        try {
            UsernameAndPasswordAuthRequest usernameAndPasswordAuthRequest=
                    new ObjectMapper().readValue(request.getInputStream(), UsernameAndPasswordAuthRequest.class);

            Authentication authentication=new UsernamePasswordAuthenticationToken(
                    usernameAndPasswordAuthRequest.getUsername(),
                    usernameAndPasswordAuthRequest.getPassword()
            );
            return authenticationManager.authenticate(authentication);

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        Date issueDate=new Date();
        Date expirationDate=java.sql.Date.valueOf(LocalDate.now().plusDays(1));
        String jti= UUID.randomUUID().toString();

        String secretKey = System.getenv("HMAC_SECRET_KEY");
        if (secretKey == null || secretKey.isEmpty()) {
            throw new IllegalStateException("Environment variable HMAC_SECRET_KEY is not set.");
        }

        String token = Jwts.builder()
                .setSubject(authResult.getName())
                .claim("authorities", authResult.getAuthorities())
                .setIssuedAt(issueDate)
                .setExpiration(expirationDate)
                .claim("jti", jti)
                .signWith(Keys.hmacShaKeyFor(secretKey.getBytes()))
                .compact();

        Cookie jwtCookie = new Cookie("token", token);
        jwtCookie.setHttpOnly(true);
        jwtCookie.setSecure(true);
        jwtCookie.setPath("/");
        jwtCookie.setMaxAge(86400); // 24 hours
        response.addCookie(jwtCookie);

        Optional<List<Token>> oldTokens=tokenRepository.getTokenByEmail(authResult.getName());
        if(oldTokens.isPresent()){
            invalidateOldTokens(oldTokens.get());
        }

        Token newToken=new Token();
        newToken.setActive(true);
        newToken.setEmail(authResult.getName());
        newToken.setCreatedAt(issueDate);
        newToken.setEndDate(expirationDate);
        newToken.setValue(token);
        newToken.setJti(jti);
        tokenRepository.save(newToken);
    }

    private void invalidateOldTokens(List<Token>oldTokens){
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
}
