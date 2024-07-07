package com.authentication.jwt_athentication.payload.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
public class JwtResponse {
    private String token;
    private String type = "Bearer";
    private Long id;
    private String username;
    private List<String> role;

    public JwtResponse(String token, Long id, String username, List<String> role) {
        this.token = token;
        this.id = id;
        this.username = username;
        this.role = role;
    }
}
