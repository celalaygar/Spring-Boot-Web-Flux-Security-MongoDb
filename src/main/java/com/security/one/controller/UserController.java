package com.security.one.controller;


import com.security.one.dto.UserResponse;
import com.security.one.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api/user")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    /**
     * GET /api/user/me → Mevcut kullanıcı bilgisi
     * Erişim: ROLE_USER, ROLE_ADMIN
     */
    @GetMapping("/me")
    public Mono<ResponseEntity<UserResponse>> getCurrentUser(@AuthenticationPrincipal UserDetails userDetails) {
        return userService.getCurrentUser(userDetails.getUsername())
                .map(ResponseEntity::ok)
                .defaultIfEmpty(ResponseEntity.notFound().build());
    }

    /**
     * GET /api/user/profile → Detaylı profil (örnek ekstra endpoint)
     */
    @GetMapping("/profile")
    public Mono<ResponseEntity<UserResponse>> getProfile(@AuthenticationPrincipal UserDetails userDetails) {
        return userService.getCurrentUser(userDetails.getUsername())
                .map(user -> ResponseEntity.ok()
                        .header("X-Role", user.getSystemRoles().toString())
                        .body(user))
                .defaultIfEmpty(ResponseEntity.notFound().build());
    }
}