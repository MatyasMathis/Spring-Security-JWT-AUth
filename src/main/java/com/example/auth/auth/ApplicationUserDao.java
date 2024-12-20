package com.example.auth.auth;

import java.util.Optional;

public interface ApplicationUserDao {
    Optional<ApplicationUser> getUserByUsername(String username);
}
