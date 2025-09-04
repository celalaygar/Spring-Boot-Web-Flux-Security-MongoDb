package com.security.one.config;

import io.jsonwebtoken.ExpiredJwtException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@Component
public class JWTAuthenticationFilter implements org.springframework.web.server.WebFilter {

    private final ServerSecurityContextRepository securityContextRepository;
    private final JWTProvider jwtProvider;
    private final ReactiveUserDetailsService userDetailsService;

    public JWTAuthenticationFilter(
            JWTProvider jwtProvider,
            ReactiveUserDetailsService userDetailsService) {
        this.jwtProvider = jwtProvider;
        this.userDetailsService = userDetailsService;
        this.securityContextRepository = new JwtServerSecurityContextRepository(jwtProvider, userDetailsService);
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        // 🔴 Durum 1: Token yok → 401 (flag: false)
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return chain.filter(exchange); // Bu, authenticationEntryPoint'e düşer
        }

        String token = authHeader.substring(7);

        // Token var ama validate edilemiyorsa
        return Mono.fromCallable(() -> {
                    jwtProvider.validateToken(token); // Bu, expired'da hata fırlatır
                    return token;
                })
                .onErrorResume(ExpiredJwtException.class, ex -> {
                    // 🟡 Durum 2: Token expired → 401 (flag: true)
                    exchange.getAttributes().put("tokenExpired", true);
                    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                    return Mono.empty();
                })
                .onErrorResume(Exception.class, ex -> {
                    // 🔴 Durum 3: Geçersiz token → 401 (flag: false)
                    exchange.getAttributes().put("tokenExpired", false);
                    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                    return Mono.empty();
                })
                .flatMap(validToken -> {
                    String email = jwtProvider.getEmailFromToken(token);
                    return userDetailsService.findByUsername(email)
                            .switchIfEmpty(Mono.defer(() -> {
                                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                                return Mono.empty();
                            }))
                            .flatMap(userDetails -> {
                                var auth = new UsernamePasswordAuthenticationToken(
                                        userDetails, null, userDetails.getAuthorities());
                                var context = new SecurityContextImpl(auth);
                                return securityContextRepository.save(exchange, context)
                                        .then(chain.filter(exchange));
                            });
                })
                .switchIfEmpty(Mono.defer(() -> chain.filter(exchange))); // 401 set edildi, chain çalışır
    }
}