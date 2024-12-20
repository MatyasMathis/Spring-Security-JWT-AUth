package com.example.auth.jwt.repository;

import com.example.auth.jwt.entity.Token;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface TokenRepository extends JpaRepository<Token,Long> {
    Optional<List<Token>> getTokenByEmail(String email);
    Optional<Token> findOneByJti(String jti);
}
