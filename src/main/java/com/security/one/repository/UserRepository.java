package com.security.one.repository;


import com.security.one.entity.User;
import org.springframework.data.mongodb.repository.ReactiveMongoRepository;
import reactor.core.publisher.Mono;

public interface UserRepository extends ReactiveMongoRepository<User, String> {
    Mono<User> findByUsername(String username);
    Mono<User> findByEmail(String email);
    Mono<User> findByEmailChangeToken(String token);
    Mono<User> findByResetPasswordToken(String token);


}
