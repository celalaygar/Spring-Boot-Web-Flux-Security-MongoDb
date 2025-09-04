package com.security.one.service;


import com.security.one.dto.UserResponse;
import com.security.one.entity.User;
import com.security.one.repository.UserRepository;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
public class UserService {

    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public Mono<UserResponse> getCurrentUser(String email) {

        return  getAuthUser().map(this::toUserResponse);
    }

    private UserResponse toUserResponse(User user) {
        UserResponse response = new UserResponse();
        response.setId(user.getId());
        response.setEmail(user.getEmail());
        response.setUsername(user.getUsername());
        response.setFirstname(user.getFirstname());
        response.setLastname(user.getLastname());
        response.setSystemRoles(user.getSystemRoles());
        response.setCreatedAt(user.getCreatedAt());
        response.setUpdatedAt(user.getUpdatedAt());
        return response;
    }

    public Mono<User> getAuthUser() {
        return ReactiveSecurityContextHolder.getContext()
                .map(securityContext -> {
                    String email = securityContext.getAuthentication().getName();
                    return userRepository.findByEmail(email); // Bu, Mono<User> döndürüyor
                })
                .flatMap(userMono -> userMono); // Mono<User> döndürüyor
    }
}