package com.security.one.service;

import com.security.one.entity.SystemRole;
import com.security.one.repository.UserRepository;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.stream.Collectors;

@Service
public class MongoUserDetailsService implements ReactiveUserDetailsService {

    private final UserRepository userRepository;

    public MongoUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public Mono<UserDetails> findByUsername(String email) {
        return userRepository.findByEmail(email)
                .switchIfEmpty(Mono.empty())
                .map(user -> org.springframework.security.core.userdetails.User
                        .withUsername(user.getEmail())
                        .password(user.getPassword())
                        .authorities(user.getSystemRoles().stream()
                                .map(role -> new SimpleGrantedAuthority( role.name()))
                                .collect(Collectors.toList()))
                        .accountLocked(user.getSystemRoles().contains(SystemRole.ROLE_DELETED))
                        .disabled(user.getSystemRoles().contains(SystemRole.ROLE_PASSIVE))
                        .build()
                );
    }
}