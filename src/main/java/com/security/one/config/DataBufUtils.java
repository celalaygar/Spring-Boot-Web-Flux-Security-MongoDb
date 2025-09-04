package com.security.one.config;

import org.reactivestreams.Publisher;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

public class DataBufUtils {

    public static Mono<String> readRequestBody(ServerWebExchange exchange) {
        return exchange.getRequest().getBody()
                .map(dataBuffer -> {
                    byte[] bytes = new byte[dataBuffer.readableByteCount()];
                    dataBuffer.read(bytes);
                    org.springframework.core.io.buffer.DataBufferUtils.release(dataBuffer);
                    return new String(bytes, StandardCharsets.UTF_8);
                })
                .reduce("", (s1, s2) -> s1 + s2);
    }

    public static Mono<String> readResponseBody(Publisher<? extends DataBuffer> body, // ✅ ? extends DataBuffer
                                                org.springframework.core.io.buffer.DataBufferFactory bufferFactory) {
        return Flux.from(body)
                .map(dataBuffer -> {
                    byte[] bytes = new byte[dataBuffer.readableByteCount()];
                    dataBuffer.read(bytes);
                    org.springframework.core.io.buffer.DataBufferUtils.release(dataBuffer);
                    return new String(bytes, StandardCharsets.UTF_8);
                })
                .reduce("", (s1, s2) -> s1 + s2);
    }
}