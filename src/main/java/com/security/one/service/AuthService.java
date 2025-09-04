package com.security.one.service;
import com.security.one.config.JWTProvider;
import com.security.one.dto.RegisterRequest;
import com.security.one.entity.SystemRole;
import com.security.one.entity.User;
import com.security.one.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JWTProvider jwtProvider;

    public Mono<String> register(RegisterRequest request) {
        return userRepository.findByEmail(request.getEmail())
                .hasElement()
                .flatMap(exists -> {
                    if (exists) {
                        return Mono.error(new RuntimeException("Email already exists"));
                    }


                    User user = User.builder()
                            .email(request.getEmail())
                            .firstname(request.getFirstname())
                            .lastname(request.getLastname())
                            .username(request.getUsername())
                            .password(passwordEncoder.encode(request.getPassword()))
                            .systemRoles( Set.of(SystemRole.ROLE_USER))
                            .createdAt(LocalDateTime.now())
                            .build();

                    return userRepository.save(user)
                            .map(u -> jwtProvider.generateToken(u.getEmail(), u.getSystemRoles()));
                });
    }

    public Mono<String> login(String email, String password) {
        return userRepository.findByEmail(email)
                .switchIfEmpty(Mono.error(new RuntimeException("User not found")))
                .flatMap(user -> {
                    if (!passwordEncoder.matches(password, user.getPassword())) {
                        return Mono.error(new RuntimeException("Invalid password"));
                    }
                    return Mono.just(jwtProvider.generateToken(user.getEmail(), user.getSystemRoles()));
                });
    }
}