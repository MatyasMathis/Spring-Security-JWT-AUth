package com.example.auth.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class ApplicationUserDbService implements ApplicationUserDao{
    @Autowired
    private ApplicationUserRepository applicationUserRepository;

    @Override
    public Optional<ApplicationUser> getUserByUsername(String username) {
        Optional<ApplicationUser> applicationUser=applicationUserRepository.findApplicationUserByUsername(username);
        return applicationUser;
    }
}
