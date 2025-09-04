package com.security.one.config;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;
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
        String token = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        // 🔴 Durum 1: Token yok
        if (ObjectUtils.isEmpty(token)) {
            exchange.getAttributes().put("tokenExpired", false);
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return chain.filter(exchange);
        }

        // 🔍 Durum 2: Token var → validate et
        return Mono.fromCallable(() -> {
                    if (!jwtProvider.validateToken(token)) {
                        throw new IllegalArgumentException("Invalid token");
                    }
                    return token;
                })
                .onErrorResume(ExpiredJwtException.class, ex -> {
                    // 🟡 Expired token
                    exchange.getAttributes().put("tokenExpired", true);
                    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                    return Mono.empty();
                })
                .onErrorResume(JwtException.class, ex -> {
                    // 🔴 Malformed, unsupported, illegal arg vs.
                    exchange.getAttributes().put("tokenExpired", false);
                    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                    return Mono.empty();
                })
                .onErrorResume(Exception.class, ex -> {
                    // 🔴 Diğer tüm hatalar (genel koruma)
                    exchange.getAttributes().put("tokenExpired", false);
                    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                    return Mono.empty();
                })
                .flatMap(validToken -> {
                    // ✅ Token valid → email al
                    String email;
                    try {
                        email = jwtProvider.getEmailFromToken(token);
                    } catch (Exception e) {
                        exchange.getAttributes().put("tokenExpired", false);
                        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                        return Mono.empty();
                    }

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
                .switchIfEmpty(Mono.defer(() -> chain.filter(exchange)));
    }
}