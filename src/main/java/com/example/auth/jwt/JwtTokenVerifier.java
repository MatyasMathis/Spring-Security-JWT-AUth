package com.example.auth.jwt;

import com.example.auth.jwt.entity.Token;
import com.example.auth.jwt.repository.TokenRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.logging.log4j.util.Strings;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

public class JwtTokenVerifier extends OncePerRequestFilter {
    private TokenRepository tokenRepository;

    public JwtTokenVerifier(TokenRepository tokenRepository) {
        this.tokenRepository = tokenRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        Cookie[] cookies = request.getCookies();

        if (cookies == null) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "No cookies found, authentication required");
            return;
        }

        String token = Arrays.stream(cookies)
                .filter(cookie -> "token".equals(cookie.getName()))
                .map(Cookie::getValue)
                .findFirst()
                .orElse(null);

        if(!Strings.isNotEmpty(token)){
            filterChain.doFilter(request,response);
            return;
        }

        try {
            String secretKey = System.getenv("HMAC_SECRET_KEY");
            Jws<Claims> claimsJws= Jwts.parser()
                    .setSigningKey(Keys.hmacShaKeyFor(secretKey.getBytes()))
                    .build().parseClaimsJws(token);

            Claims body=claimsJws.getBody();
            String jti = body.get("jti", String.class);
            String username=body.getSubject();

            Optional<Token> jwtToken=tokenRepository.findOneByJti(jti);
            if(!jwtToken.isPresent() || !jwtToken.get().getActive()){
                response.sendRedirect("/login");
                return;
            }

            var authorities=(List<Map<String,String>>) body.get("authorities");

            List<SimpleGrantedAuthority> simpleGrantedAuthoritySet= authorities.stream()
                    .map(m->new SimpleGrantedAuthority(m.get("authority")))
                    .collect(Collectors.toList());

            Authentication authentication= new UsernamePasswordAuthenticationToken(
                    username,
                    null,
                    simpleGrantedAuthoritySet
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (JwtException e){
            throw new IllegalStateException(String.format("Token is incorrect"));
        }

        filterChain.doFilter(request,response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return Boolean.TRUE.equals(request.getRequestURI().equals("/login") ||
                request.getRequestURI().equals("/app/login"));
    }
}
