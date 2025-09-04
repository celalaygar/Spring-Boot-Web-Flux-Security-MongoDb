package com.security.one.config;

import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

@Component
public class CustomAuthenticationEntryPoint implements ServerAuthenticationEntryPoint {

    @Override
    public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException ex) {
        // exchange.getAttribute ile flag kontrol et
        Boolean tokenExpired = (Boolean) exchange.getAttributes().get("tokenExpired");

        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        exchange.getResponse().getHeaders().set("Content-Type", "application/json");

        String body;
        if (Boolean.TRUE.equals(tokenExpired)) {
            body = "{\"error\":\"Unauthorized\",\"message\":\"Token expired\",\"tokenExpired\":true}";
        } else {
            body = "{\"error\":\"Unauthorized\",\"message\":\"Missing or invalid token\",\"tokenExpired\":false}";
        }

        DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(body.getBytes(StandardCharsets.UTF_8));
        return exchange.getResponse().writeWith(Mono.just(buffer));
    }
}