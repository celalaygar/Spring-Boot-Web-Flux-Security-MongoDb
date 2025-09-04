package com.security.one.config;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
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

        // Token yoksa → geç
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return chain.filter(exchange);
        }

        String token = authHeader.substring(7);

        // Token geçersizse → 401
        if (!jwtProvider.validateToken(token)) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String email = jwtProvider.getEmailFromToken(token);

        return userDetailsService.findByUsername(email)
                .switchIfEmpty(Mono.defer(() -> {
                    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                    return Mono.error(new BadCredentialsException("User not found"));
                }))
                .flatMap(userDetails -> {
                    var auth = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                    var context = new SecurityContextImpl(auth);

                    // ✅ save() bittikten sonra chain.filter() çalışır
                    return securityContextRepository
                            .save(exchange, context) // SecurityContext kurulur
                            .then(chain.filter(exchange)); // Artık @AuthenticationPrincipal çalışır
                })
                .onErrorResume(ex -> {
                    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                    return exchange.getResponse().setComplete();
                });
    }
}