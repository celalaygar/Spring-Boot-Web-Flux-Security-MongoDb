package com.security.one.config;

import com.security.one.service.ApiLoggingService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.reactivestreams.Publisher;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

@Component
@RequiredArgsConstructor
@Slf4j
public class LoggingFilter implements WebFilter {

    private final ApiLoggingService loggingService;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();

        if (!path.startsWith("/api/")) {
            return chain.filter(exchange);
        }

        String method = request.getMethod().name();
        String requestHeaders = request.getHeaders().toString();
        String token = extractToken(request);
        String email = extractEmailFromToken(token);

        return DataBufUtils.readRequestBody(exchange)
                .defaultIfEmpty("")
                .flatMap(requestBody -> {
                    loggingService.logRequest(method, path, requestBody, requestHeaders, token, email)
                            .subscribe(); // fire-and-forget

                    // Wrap request
                    ServerHttpRequest mutatedRequest = new ServerHttpRequestDecorator(request) {
                        @Override
                        public Flux<DataBuffer> getBody() {
                            if (requestBody.isEmpty()) return Flux.empty();
                            DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(
                                    requestBody.getBytes(StandardCharsets.UTF_8));
                            return Flux.just(buffer);
                        }
                    };

                    // Wrap response
                    ServerHttpResponse originalResponse = exchange.getResponse();
                    ServerHttpResponseDecorator decoratedResponse = new ServerHttpResponseDecorator(originalResponse) {
                        @Override
                        public Mono<Void> writeWith(Publisher<? extends DataBuffer> body) { // ✅ ? extends DataBuffer
                            Flux<? extends DataBuffer> bufferFlux = Flux.from(body);

                            return DataBufUtils.readResponseBody(bufferFlux, originalResponse.bufferFactory())
                                    .flatMap(responseBody -> {
                                        String responseHeaders = getHeaders().toString();
                                        int statusCode = getStatusCode() != null ? getStatusCode().value() : 500;

                                        return loggingService.logResponse(responseBody, responseHeaders, statusCode)
                                                .then(Mono.just(responseBody));
                                    })
                                    .flatMap(responseBody -> {
                                        DataBuffer buffer = originalResponse.bufferFactory().wrap(
                                                responseBody.getBytes(StandardCharsets.UTF_8));
                                        return super.writeWith(Flux.just(buffer));
                                    });
                        }
                    };

                    return chain.filter(exchange.mutate()
                            .request(mutatedRequest)
                            .response(decoratedResponse)
                            .build());
                });
    }

    private String extractToken(ServerHttpRequest request) {
        String auth = request.getHeaders().getFirst("Authorization");
        if (auth != null && auth.startsWith("Bearer ")) {
            return auth.substring(7);
        }
        return null;
    }

    private String extractEmailFromToken(String token) {
        if (token == null) return "anonymous";
        // Gerçek decode için JWTProvider kullanılmalı
        return "decoded-email@example.com"; // Mock
    }
}