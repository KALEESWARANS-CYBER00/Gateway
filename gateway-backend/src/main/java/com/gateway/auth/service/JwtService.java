package com.gateway.auth.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class JwtService {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private long expiration; // in milliseconds

    public String getSecret() {
        return secret;
    }

    public long getExpiration() {
        return expiration;
    }

    // Use the `secret` and `expiration` in your token generation logic...
}
