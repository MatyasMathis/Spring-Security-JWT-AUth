package com.example.auth.security;

import com.example.auth.auth.ApplicationUserService;
import com.example.auth.jwt.JwtTokenVerifier;
import com.example.auth.jwt.JwtUsernameAndPasswordAuthenticationFilter;
import com.example.auth.jwt.repository.TokenRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig {
    private PasswordEncoder passwordEncoder;
    private ApplicationUserService applicationUserService;
    @Autowired
    private TokenRepository tokenRepository;

    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder, ApplicationUserService applicationUserService) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,AuthenticationConfiguration authenticationConfiguration) throws Exception {
        AuthenticationManager authenticationManager = authenticationManager(authenticationConfiguration);

        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(sessionManagement ->
                        sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/login", "/api/login", "/home").permitAll() // Public endpoints
                        .anyRequest().authenticated() // Secured endpoints
                )
                .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager,tokenRepository))
                .addFilterAfter(new JwtTokenVerifier(tokenRepository), JwtUsernameAndPasswordAuthenticationFilter.class);

        return http.build();
//                .formLogin((form) -> form
//                        .loginPage("/login")
//                        .permitAll()
//                        .defaultSuccessUrl("/home",false)
//                )
//                .logout((logout) -> logout.permitAll())
//                .exceptionHandling((exceptions) -> exceptions
//                        .accessDeniedPage("/access-denied") // Custom access denied page
//                );
//
//        return http.build();
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider(){
        DaoAuthenticationProvider provider=new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);
        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
}
