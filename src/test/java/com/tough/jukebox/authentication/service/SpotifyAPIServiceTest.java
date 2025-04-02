package com.tough.jukebox.authentication.service;

import com.tough.jukebox.authentication.config.SpotifyConfig;
import com.tough.jukebox.authentication.model.SpotifyToken;
import com.tough.jukebox.authentication.model.User;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.web.client.RestTemplate;

import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SpotifyAPIServiceTest {

    @Mock
    RestTemplate restTemplate;

    @Mock
    SpotifyConfig spotifyConfig;

    @InjectMocks
    SpotifyAPIService spotifyAPIService;

    @Test
    void testRefreshAccessTokenSuccess() {
        mockSpotifyTokenRefreshResponse();

        SpotifyToken token = spotifyAPIService.refreshAccessToken("test-refresh-token");

        assertEquals("test-access-token", token.getAccessToken());
        assertEquals("test-refresh-token", token.getRefreshToken());
        assertTrue(token.getTokenExpiry().isAfter(Instant.now()));
    }

    @Test
    void testFetchUserDetailsSuccess() {
        when(spotifyConfig.getSpotifyCurrentUserUri()).thenReturn("http://test-spotify-user-uri");

        ResponseEntity<Map<String, Object>> responseEntity = new ResponseEntity<>(
                Map.of(
                        "id", "test-id",
                        "email", "test@email.address",
                        "display_name", "test-display-name"
                ),
                HttpStatus.OK);

        when(restTemplate.exchange(
                eq("http://test-spotify-user-uri"),
                eq(HttpMethod.GET),
                any(HttpEntity.class),
                eq(new ParameterizedTypeReference<Map<String, Object>>() {})
        )).thenReturn(responseEntity);

        User user = spotifyAPIService.fetchUserDetails("test-access-token");

        assertEquals("test-id", user.getSpotifyUserId());
        assertEquals("test@email.address", user.getEmailAddress());
        assertEquals("test-display-name", user.getDisplayName());
    }

    @Test
    void testFetchUserDetailsFailureEmptyBody() {
        when(spotifyConfig.getSpotifyCurrentUserUri()).thenReturn("http://test-spotify-user-uri");

        ResponseEntity<Map<String, Object>> responseEntity = new ResponseEntity<>(
                null,
                HttpStatus.OK);

        when(restTemplate.exchange(
                eq("http://test-spotify-user-uri"),
                eq(HttpMethod.GET),
                any(HttpEntity.class),
                eq(new ParameterizedTypeReference<Map<String, Object>>() {})
        )).thenReturn(responseEntity);

        User user = spotifyAPIService.fetchUserDetails("test-access-token");

        assertNull(user);
    }

    @Test
    void testFetchUserDetailsFailure404NotFound() {
        when(spotifyConfig.getSpotifyCurrentUserUri()).thenReturn("http://test-spotify-user-uri");

        ResponseEntity<Map<String, Object>> responseEntity = new ResponseEntity<>(
                null,
                HttpStatus.NOT_FOUND);

        when(restTemplate.exchange(
                eq("http://test-spotify-user-uri"),
                eq(HttpMethod.GET),
                any(HttpEntity.class),
                eq(new ParameterizedTypeReference<Map<String, Object>>() {})
        )).thenReturn(responseEntity);

        User user = spotifyAPIService.fetchUserDetails("test-access-token");

        assertNull(user);
    }

    @Test
    void testAuthenticateSuccess() {
        mockSpotifyTokenRefreshResponse();

        SpotifyToken token = spotifyAPIService.authenticate("test-auth-code");

        assertEquals("test-access-token", token.getAccessToken());
        assertEquals("test-refresh-token", token.getRefreshToken());
        assertTrue(token.getTokenExpiry().isAfter(Instant.now()));
    }

    private void mockSpotifyTokenRefreshResponse() {
        when(spotifyConfig.getSpotifyTokenUri()).thenReturn("http://test-spotify-token-uri");

        ResponseEntity<Map<String, Object>> responseEntity = new ResponseEntity<>(
                Map.of(
                        "expires_in", 3600,
                        "access_token", "test-access-token",
                        "refresh_token", "test-refresh-token"
                ),
                HttpStatus.OK);

        when(restTemplate.exchange(
                eq("http://test-spotify-token-uri"),
                eq(HttpMethod.POST),
                any(HttpEntity.class),
                eq(new ParameterizedTypeReference<Map<String, Object>>() {})
        )).thenReturn(responseEntity);
    }
}
