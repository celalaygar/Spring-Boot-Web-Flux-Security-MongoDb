package com.security.one.dto;

import com.security.one.entity.SystemRole;
import lombok.Data;
import java.time.LocalDateTime;
import java.util.Set;

@Data
public class UserResponse {
    private String id;
    private String email;
    private String username;
    private String firstname;
    private String lastname;
    private Set<SystemRole> systemRoles;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
}