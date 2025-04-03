package com.tough.jukebox.authentication.security;

import com.tough.jukebox.authentication.config.SecurityConfig;
import io.jsonwebtoken.security.UnsupportedKeyException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JwtUtilTest {

    @Mock
    private SecurityConfig securityConfig;

    @InjectMocks
    private JwtUtil jwtUtil;

    private static final String TEST_SECRET_KEY = "1QxfP27e3kyfPIf5pl4aHu7BkGOpx93o";
    private static final String TEST_USER_ID = "test-user-id";

    @Test
    void testCreateTokenSuccess() {
        when(securityConfig.getSecretKey()).thenReturn(TEST_SECRET_KEY);

        String jwt = jwtUtil.createToken(TEST_USER_ID);

        assertNotNull(jwt);
        // 110 is minimum length the jwt should be
        // Header (Base64-encoded): 43 characters, Payload (Base64-encoded): 24 characters, Signature (Base64-encoded): 43 characters
        assertTrue(jwt.length() > 110);
    }

    @Test
    void testCreateTokenFailureUnsupportedKeyException() {
        when(securityConfig.getSecretKey()).thenReturn("invalid-secret-key");

        assertThrows(UnsupportedKeyException.class, () -> {
            jwtUtil.createToken(TEST_USER_ID);
        });
    }

    @Test
    void testValidateTokenSuccess() {
        when(securityConfig.getSecretKey()).thenReturn(TEST_SECRET_KEY);

        String jwt = jwtUtil.createToken(TEST_USER_ID);

        assertTrue(jwtUtil.validateToken(jwt));
    }

    @Test
    void testValidateTokenFailureInvalidToken() {
        when(securityConfig.getSecretKey()).thenReturn(TEST_SECRET_KEY);
        assertFalse(jwtUtil.validateToken("invalid-jwt"));
    }

    @Test
    void testValidateTokenFailureNullToken() {
        when(securityConfig.getSecretKey()).thenReturn(TEST_SECRET_KEY);
        assertFalse(jwtUtil.validateToken(null));
    }

    @Test
    void testGetUserIdFromTokenSuccess() {
        when(securityConfig.getSecretKey()).thenReturn(TEST_SECRET_KEY);

        String jwt = jwtUtil.createToken(TEST_USER_ID);
        String userId = jwtUtil.getUserIdFromToken(jwt);

        assertEquals(TEST_USER_ID, userId);
    }

    @Test
    void testGetUserIdFromTokenFailureEmptyToken() {
        String userID = jwtUtil.getUserIdFromToken(null);
        assertTrue(userID.isEmpty());
    }
}
