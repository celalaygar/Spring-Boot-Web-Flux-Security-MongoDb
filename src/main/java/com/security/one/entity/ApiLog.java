package com.security.one.entity;


import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.LocalDateTime;

@Document("api_logs")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ApiLog {
    @Id
    private String id;
    private String method;
    private String uri;
    private String requestBody;
    private String requestHeaders;
    private String responseBody;
    private String responseHeaders;
    private String token;
    private String email;
    private Integer statusCode;
    private LocalDateTime timestamp;
}
