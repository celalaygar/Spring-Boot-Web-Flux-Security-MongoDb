package com.security.one.repository;


import com.security.one.entity.ApiLog;
import org.springframework.data.mongodb.repository.ReactiveMongoRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

@Repository
public interface ApiLogRepository extends ReactiveMongoRepository<ApiLog, String> {
    Mono<ApiLog> findFirstByOrderByTimestampDesc();

}