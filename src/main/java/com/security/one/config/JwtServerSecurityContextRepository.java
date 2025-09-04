package com.security.one.config;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class JwtServerSecurityContextRepository implements ServerSecurityContextRepository {

    private final JWTProvider jwtProvider;
    private final ReactiveUserDetailsService userDetailsService;

    public JwtServerSecurityContextRepository(JWTProvider jwtProvider, ReactiveUserDetailsService userDetailsService) {
        this.jwtProvider = jwtProvider;
        this.userDetailsService = userDetailsService;
    }

    @Override
    public Mono<Void> save(ServerWebExchange exchange, SecurityContext context) {
        // ✅ Context kaydetme işlemi burada yapılır
        // NoOp değil, ama biz `NoOpServerSecurityContextRepository.getInstance()` kullanmıyoruz
        // Bu custom repo, context'i `exchange`'e koyar
        exchange.getAttributes().put("org.springframework.security.core.context.SecurityContext", context);
        return Mono.empty();
    }

    @Override
    public Mono<SecurityContext> load(ServerWebExchange exchange) {
        String token = exchange.getRequest().getHeaders().getFirst("Authorization");
        if (ObjectUtils.isEmpty(token)) {
            return Mono.empty();
        }
        String email;
        try {
            email = jwtProvider.getEmailFromToken(token);
        } catch (Exception e) {
            return Mono.empty();
        }

        return userDetailsService.findByUsername(email)
                .flatMap(userDetails -> {
                    if (!jwtProvider.validateToken(token)) {
                        return Mono.empty();
                    }
                    var auth = new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities());
                    return Mono.just(new SecurityContextImpl(auth));
                });
    }
}