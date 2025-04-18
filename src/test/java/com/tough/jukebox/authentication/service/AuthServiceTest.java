package com.tough.jukebox.authentication.service;

import com.tough.jukebox.authentication.config.SpotifyConfig;
import com.tough.jukebox.authentication.config.WebConfig;
import com.tough.jukebox.authentication.exception.SpotifyAPIException;
import com.tough.jukebox.authentication.model.SpotifyToken;
import com.tough.jukebox.authentication.model.User;
import com.tough.jukebox.authentication.security.JwtUtil;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private SpotifyConfig spotifyConfig;

    @Mock
    private WebConfig webConfig;

    @Mock
    private JwtUtil jwtUtil;

    @Mock
    private UserService userService;

    @Mock
    private SpotifyAPIService spotifyAPIService;

    @InjectMocks
    private AuthService authService;

    @Test
    void testGetSpotifyRedirectParamsSuccessful() {
        when(spotifyConfig.getSpotifyAppClientId()).thenReturn("test-client-id");
        when(spotifyConfig.getSpotifyRedirectUri()).thenReturn("test-redirect-uri");

        Map<String, String> params = authService.getSpotifyRedirectParams();

        assertEquals("test-redirect-uri", params.get("redirectUri"));
        assertEquals("test-client-id", params.get("clientId"));
    }

    @Test
    void testLogoutSuccess() throws NoSuchAlgorithmException, InvalidKeySpecException {
        when(jwtUtil.getUserIdFromToken("test-jwt")).thenReturn("test-user-id");
        when(userService.clearUserTokens("test-user-id")).thenReturn(true);

        boolean success = authService.logOut("test-jwt");

        assertTrue(success);
    }

    @Test
    void testLogoutFailureEmptyJwt() throws NoSuchAlgorithmException, InvalidKeySpecException {
        when(jwtUtil.getUserIdFromToken(anyString())).thenReturn("");

        boolean success = authService.logOut("");

        assertFalse(success);
    }

    @Test
    void testLogoutFailureUserNotFound() throws NoSuchAlgorithmException, InvalidKeySpecException {
        when(jwtUtil.getUserIdFromToken(anyString())).thenReturn("test-user-id");
        when(userService.clearUserTokens(anyString())).thenReturn(false);

        boolean success = authService.logOut("test-jwt");

        assertFalse(success);
    }

    @Test
    void testCompleteAuthenticationNewUserProfileSuccess() throws SpotifyAPIException, NoSuchAlgorithmException, InvalidKeySpecException {
        SpotifyToken spotifyToken = mockSpotifyAPIAuthenticate();

        when(webConfig.getFrontendRedirectUri()).thenReturn("http://127.0.0.1/test-frontend-redirect-uri");

        User user = new User();
        user.setSpotifyUserId("test-spotify-user-id");
        when(spotifyAPIService.fetchUserDetails(any(String.class))).thenReturn(user);

        when(userService.getUserBySpotifyUserId(anyString())).thenReturn(Optional.empty());
        doNothing().when(userService).updateSpotifyTokens(user, spotifyToken);

        when(jwtUtil.createToken(anyString())).thenReturn("test-jwt");

        Map<String, String> response = authService.completeAuthentication("spotify-auth-code");

        Map<String, String> authenticationMap = new HashMap<>();
        authenticationMap.put("jwt", "test-jwt");
        authenticationMap.put("redirectUri", "http://127.0.0.1/test-frontend-redirect-uri");

        assertEquals(authenticationMap, response);
    }

    @Test
    void testCompleteAuthenticationExistingUserNewSessionSuccess() throws SpotifyAPIException, NoSuchAlgorithmException, InvalidKeySpecException {
        SpotifyToken spotifyToken = mockSpotifyAPIAuthenticate();

        when(webConfig.getFrontendRedirectUri()).thenReturn("http://127.0.0.1/test-frontend-redirect-uri");

        User user = new User();
        user.setSpotifyUserId("test-spotify-user-id");
        when(spotifyAPIService.fetchUserDetails(any(String.class))).thenReturn(user);

        when(userService.getUserBySpotifyUserId(anyString())).thenReturn(Optional.of(user));
        doNothing().when(userService).updateSpotifyTokens(user, spotifyToken);

        when(jwtUtil.createToken(anyString())).thenReturn("test-jwt");

        Map<String, String> response = authService.completeAuthentication("spotify-auth-code");

        Map<String, String> authenticationMap = new HashMap<>();
        authenticationMap.put("jwt", "test-jwt");
        authenticationMap.put("redirectUri", "http://127.0.0.1/test-frontend-redirect-uri");

        assertEquals(authenticationMap, response);
    }

    @Test
    void testCompleteAuthenticationFailureNoUserReturnedFromSpotify() throws SpotifyAPIException {

        mockSpotifyAPIAuthenticate();
        when(webConfig.getFrontendRedirectUri()).thenReturn("http://127.0.0.1/test-frontend-redirect-uri");

        when(spotifyAPIService.fetchUserDetails(any(String.class))).thenThrow(new SpotifyAPIException("No User Returned from Spotify"));

        assertThrows(SpotifyAPIException.class, () -> authService.completeAuthentication("spotify-auth-code"));
    }

    private SpotifyToken mockSpotifyAPIAuthenticate() throws SpotifyAPIException {

        SpotifyToken spotifyToken = new SpotifyToken();
        spotifyToken.setAccessToken("test-access-token");
        spotifyToken.setRefreshToken("test-refresh-token");
        spotifyToken.setTokenExpiry(Instant.now().plusSeconds(3600));

        when(spotifyAPIService.authenticate(anyString())).thenReturn(spotifyToken);

        return spotifyToken;
    }
}