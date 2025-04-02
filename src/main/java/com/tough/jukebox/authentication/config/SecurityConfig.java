package com.tough.jukebox.authentication.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SecurityConfig {

    @Value(value = "${JWT_SECRET_KEY}")
    private String secretKey;

    public String getSecretKey() { return secretKey; }
}
