package com.tough.jukebox.authentication.security;

import com.tough.jukebox.authentication.config.SecurityConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JwtUtilTest {

    @Mock
    private SecurityConfig securityConfig;

    @InjectMocks
    private JwtUtil jwtUtil;

    private static final String TEST_PRIVATE_KEY = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDH9CNkW2jHu+5pRifLTgvaARp2z+ruPQkuP3YSbbZnPF+m2rpPpLrFQdr/yseBDYJwK1DAC6Xwk28U0x0Ax5UUKVBviq3yF/M1BBl1w0zMUs+Y36eNPU3Ofit7YDsEUEQ29X6tjKCxtHKCXbqOUIg1YZk0CpzARg1WwoDw2Jn/yDkjLdhgf1NOSxa8LE7/FN8I/6WgO7K53ZWKIl/y6vdlsGVfAoB17wBoCOkHf45TwRNxd0eD/pHFMRYU50HwY1osg8xkiZgL0VZVTQZ0Dyi9d8ZbJgU/anAx1mdQZDsu7XfFa1Ej1tC4CznOe9Q4sNQTXseVSNnl2PfAm7dWkz0DAgMBAAECggEBALCCft+vpb5z0tFR4f0hh2rKAI+TmWL3tGwED3nTKerWK+YCPefilhFdwjJ90kHFKDlWs3Dkl3bY3301o+u1Q4/JrLzaYhVNOR+637LKVbgk/ieIf8M5s76uODowR8jWBnGxo0MW2iAlF9SnYvEQfD0LTA/Zsmg1Lr9A8kwqGT/l8gEc5csjAZlhX3xfPx/5S7CTpu/8v8H50fiaaHWgLQhFN94T8Klr49Lt4Td+oxZwRlLGY4GBg8acu67L/Ve1l0UDROdhA6tsc2YMGbcXaESmyRPRWfof2G23bgCojOfFC2bf/gwwyU4r+8pX1EJcxvP5WsP9uwQIqBJSgTRYGqECgYEA+Gcrp5+ojynuu5gJcGJltS4pYLAc5HqDL7U4Ih1yiTxf2fGZ19UXcg+OpfvDyyKGO+JKYjt2rY3jofGwA2gEcCwG8brOAWo+f1+da9PiyPFbkZ36zF4BOmEEytxyEqcOqeqGRQrrUuDCzx+SyOjEsPeLl0pHjCvLjzi9wIX/uNMCgYEAzhGkSap5z6rfTk4qhu31/v/LC5G/4+5lIO/W6a7vRRUB1PzGiC/cOk6BQvkvOLzmMnUj0HSM+8CId/wnPQePHsWaC9pcCxz1wdG544be335yVef4VMGGcHrfW0Ej1LqAYe3xUE/9ZtywX6VU9WhVw97Ooc1AxX/fspDNklGtzRECgYAnDRko1gnKz/3PEhzRxTZWIHay050HMldzZZr4igaampo7Cid0bfSsotN7NrRWOAxAV9f3z39d04OozvUr4+tmsxU4ZXTDdi9zGNYHwJzTmFYb82kdPd4VjnERb0yjsA23Gr6XFhtewST/KOiLm0RoydHxK+VJnQz4bCQwoyBLrwKBgA5sR65sQyhY0lZdvDZDc4NMjf6aTe77IZLjlow2lUKljMJGivK/Ps/J7NwuKrLy7b28Wyxc6/025ZZYTLrFy6ugsv5/Yw/YEA9nyXX2W6US6Ze/q67q+KjowLdXYNWj1BaGm+w+HQNVEPcw0Dh4+//AmX/TqOPp5lNONUU3eE2xAoGAYo+ceKFVkwM6GcrAHSAuXxu2zZ7B8GMXEcSMkuKMtM1OPaBSoo7WjZDyRCQGn7CmmnTVOc+xwJzN7ka7EcWBj6uw2GuZdo3nTVSbI5CP4z1SvIDPwH56p48JhNVccyp7xt2ZQHiik1yWSFbfkjQUK8SfgUQ8scIbiPyUG/L1RSQ=";
    private static final String TEST_PUBLIC_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx/QjZFtox7vuaUYny04L2gEads/q7j0JLj92Em22Zzxfptq6T6S6xUHa/8rHgQ2CcCtQwAul8JNvFNMdAMeVFClQb4qt8hfzNQQZdcNMzFLPmN+njT1Nzn4re2A7BFBENvV+rYygsbRygl26jlCINWGZNAqcwEYNVsKA8NiZ/8g5Iy3YYH9TTksWvCxO/xTfCP+loDuyud2ViiJf8ur3ZbBlXwKAde8AaAjpB3+OU8ETcXdHg/6RxTEWFOdB8GNaLIPMZImYC9FWVU0GdA8ovXfGWyYFP2pwMdZnUGQ7Lu13xWtRI9bQuAs5znvUOLDUE17HlUjZ5dj3wJu3VpM9AwIDAQAB";
    private static final String TEST_USER_ID = "test-user-id";

    public static String getTestPrivateKey() {
        return TEST_PRIVATE_KEY;
    }

    public static String getTestPublicKey() {
        return TEST_PUBLIC_KEY;
    }

    @Test
    void testCreateTokenSuccess() throws NoSuchAlgorithmException, InvalidKeySpecException {
        when(securityConfig.getPrivateKey()).thenReturn(getTestPrivateKey());

        String jwt = jwtUtil.createToken(TEST_USER_ID);

        assertNotNull(jwt);
        // 110 is minimum length the jwt should be
        // Header (Base64-encoded): 43 characters, Payload (Base64-encoded): 24 characters, Signature (Base64-encoded): 43 characters
        assertTrue(jwt.length() > 110);
    }

    @Test
    void testCreateTokenFailureUnsupportedKeyException() {
        when(securityConfig.getPrivateKey()).thenReturn("invalid-secret-key");

        assertThrows(IllegalArgumentException.class, () -> {
            jwtUtil.createToken(TEST_USER_ID);
        });
    }

    @Test
    void testValidateTokenSuccess() throws NoSuchAlgorithmException, InvalidKeySpecException {
        when(securityConfig.getPrivateKey()).thenReturn(getTestPrivateKey());
        when(securityConfig.getPublicKey()).thenReturn(getTestPublicKey());

        String jwt = jwtUtil.createToken(TEST_USER_ID);

        assertTrue(jwtUtil.validateToken(jwt));
    }

    @Test
    void testValidateTokenFailureInvalidToken() {
        when(securityConfig.getPublicKey()).thenReturn(getTestPublicKey());
        assertFalse(jwtUtil.validateToken("invalid-jwt"));
    }

    @Test
    void testValidateTokenFailureNullToken() {
        when(securityConfig.getPublicKey()).thenReturn(getTestPublicKey());
        assertFalse(jwtUtil.validateToken(null));
    }

    @Test
    void testGetUserIdFromTokenSuccess() throws NoSuchAlgorithmException, InvalidKeySpecException {
        when(securityConfig.getPrivateKey()).thenReturn(getTestPrivateKey());
        when(securityConfig.getPublicKey()).thenReturn(getTestPublicKey());

        String jwt = jwtUtil.createToken(TEST_USER_ID);
        String userId = jwtUtil.getUserIdFromToken(jwt);

        assertEquals(TEST_USER_ID, userId);
    }

    @Test
    void testGetUserIdFromTokenFailureEmptyToken() throws NoSuchAlgorithmException, InvalidKeySpecException {
        String userID = jwtUtil.getUserIdFromToken(null);
        assertTrue(userID.isEmpty());
    }
}
