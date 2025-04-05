package com.tough.jukebox.authentication.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SecurityConfig {

    @Value(value = "${PRIVATE_KEY}")
    private String privateKey;

    @Value(value = "${PUBLIC_KEY}")
    private String publicKey;

    public String getPrivateKey() { return privateKey; }

    public String getPublicKey() { return publicKey; }
}
