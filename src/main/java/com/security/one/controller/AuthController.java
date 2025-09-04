package com.security.one.controller;



import com.security.one.dto.AuthResponse;
import com.security.one.dto.LoginRequest;
import com.security.one.dto.RegisterRequest;
import com.security.one.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public Mono<ResponseEntity<AuthResponse>> register(@Valid @RequestBody RegisterRequest request) {
        return authService.register(request)
                .map(token -> ResponseEntity.ok(AuthResponse.builder()
                        .token(token)
                        .email(request.getEmail())
                        .username(request.getUsername())
                        .build()));
    }

    @PostMapping("/login")
    public Mono<ResponseEntity<AuthResponse>> login(@Valid @RequestBody LoginRequest request) {
        return authService.login(request.getEmail(), request.getPassword())
                .map(token -> ResponseEntity.ok(AuthResponse.builder()
                        .token(token)
                        .email(request.getEmail())
                        .build()));
    }
}