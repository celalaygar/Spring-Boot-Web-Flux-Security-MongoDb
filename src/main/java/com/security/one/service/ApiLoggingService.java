package com.security.one.service;

import com.security.one.config.JWTProvider;
import com.security.one.entity.ApiLog;
import com.security.one.repository.ApiLogRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class ApiLoggingService {

    private final ApiLogRepository logRepository;
    @Autowired
    private JWTProvider jwtProvider;

    private String extractEmailFromToken(String token) {
        if (token == null) return "anonymous";
        try {
            return jwtProvider.getEmailFromToken(token);
        } catch (Exception e) {
            return "invalid-token";
        }
    }
    public Mono<Void> logRequest(
            String method,
            String uri,
            String requestBody,
            String requestHeaders,
            String token,
            String email) {

        ApiLog log = ApiLog.builder()
                .method(method)
                .uri(uri)
                .requestBody(requestBody)
                .requestHeaders(requestHeaders)
                .token(token)
                .email(email)
                .timestamp(LocalDateTime.now())
                .build();

        return logRepository.save(log).then();
    }

    public Mono<Void> logResponse(String responseBody, String responseHeaders, int statusCode) {
        return logRepository.findFirstByOrderByTimestampDesc() // ✅ findFirst..., findTop... kaldırıldı
                .flatMap(log -> {
                    log.setResponseBody(responseBody);
                    log.setResponseHeaders(responseHeaders);
                    log.setStatusCode(statusCode);
                    return logRepository.save(log);
                })
                .then();
    }
}