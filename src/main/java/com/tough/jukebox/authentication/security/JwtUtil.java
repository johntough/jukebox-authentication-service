package com.tough.jukebox.authentication.security;

import com.tough.jukebox.authentication.config.SecurityConfig;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Date;
import java.util.List;

@Component
public class JwtUtil {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtUtil.class);

    private final SecurityConfig securityConfig;

    @Autowired
    public JwtUtil(SecurityConfig securityConfig) {
        this.securityConfig = securityConfig;
    }

    public String createToken(String userId) {

        LOGGER.info("Creating JWT token for User ID: {}", userId);

        return Jwts.builder()
                .subject(userId)
                .claim("roles", List.of("ROLE_USER"))
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60))
                .signWith(createSecretKey())
                .compact();
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser()
                    .verifyWith(createSecretKey())
                    .build()
                    .parseSignedClaims(token);
            // TODO: add in expiry check
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    public String getUserIdFromToken(String token) {

        if (token != null && !token.isEmpty()) {
            Claims claims = Jwts.parser()
                    .verifyWith(createSecretKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            return claims.getSubject();
        } else {
            return "";
        }
    }

    private SecretKey createSecretKey() {
        byte[] keyBytes = securityConfig.getSecretKey().getBytes();
        return new SecretKeySpec(keyBytes, "HmacSHA256");
    }

    private boolean isTokenExpired(String token) {
        return getExpirationDateFromToken(token).before(new Date());
    }

    private Date getExpirationDateFromToken(String token) {

        Claims claims = Jwts.parser()
                .verifyWith(createSecretKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();

        return claims.getExpiration();
    }
}