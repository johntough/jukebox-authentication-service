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
    void testLogoutSuccess() {
        when(jwtUtil.getUserIdFromToken("test-jwt")).thenReturn("test-user-id");
        when(userService.clearUserTokens("test-user-id")).thenReturn(true);

        boolean success = authService.logOut("test-jwt");

        assertTrue(success);
    }

    @Test
    void testLogoutFailureEmptyJwt() {
        when(jwtUtil.getUserIdFromToken(anyString())).thenReturn("");

        boolean success = authService.logOut("");

        assertFalse(success);
    }

    @Test
    void testLogoutFailureUserNotFound() {
        when(jwtUtil.getUserIdFromToken(anyString())).thenReturn("test-user-id");
        when(userService.clearUserTokens(anyString())).thenReturn(false);

        boolean success = authService.logOut("test-jwt");

        assertFalse(success);
    }

    @Test
    void testCompleteAuthenticationNewUserProfileSuccess() throws SpotifyAPIException {
        SpotifyToken spotifyToken = mockSpotifyAPIAuthenticate();

        when(webConfig.getFrontendRedirectUri()).thenReturn("http://127.0.0.1/test-frontend-redirect-uri");
        when(jwtUtil.getUserIdFromToken(anyString())).thenReturn("");

        User user = new User();
        user.setSpotifyUserId("test-spotify-user-id");
        when(spotifyAPIService.fetchUserDetails(any(String.class))).thenReturn(user);

        when(userService.getUserBySpotifyUserId(anyString())).thenReturn(Optional.empty());
        doNothing().when(userService).updateUserTokens(user, spotifyToken);

        when(jwtUtil.createToken(anyString())).thenReturn("test-jwt");

        Map<String, String> response = authService.completeAuthentication("spotify-auth-code", "");

        Map<String, String> authenticationMap = new HashMap<>();
        authenticationMap.put("jwt", "test-jwt");
        authenticationMap.put("redirectUri", "http://127.0.0.1/test-frontend-redirect-uri");

        assertEquals(authenticationMap, response);
    }

    @Test
    void testCompleteAuthenticationExistingUserNewSessionSuccess() throws SpotifyAPIException {
        SpotifyToken spotifyToken = mockSpotifyAPIAuthenticate();

        when(webConfig.getFrontendRedirectUri()).thenReturn("http://127.0.0.1/test-frontend-redirect-uri");
        when(jwtUtil.getUserIdFromToken(anyString())).thenReturn("");

        User user = new User();
        user.setSpotifyUserId("test-spotify-user-id");
        when(spotifyAPIService.fetchUserDetails(any(String.class))).thenReturn(user);

        when(userService.getUserBySpotifyUserId(anyString())).thenReturn(Optional.of(user));
        doNothing().when(userService).updateUserTokens(user, spotifyToken);

        when(jwtUtil.createToken(anyString())).thenReturn("test-jwt");

        Map<String, String> response = authService.completeAuthentication("spotify-auth-code", "");

        Map<String, String> authenticationMap = new HashMap<>();
        authenticationMap.put("jwt", "test-jwt");
        authenticationMap.put("redirectUri", "http://127.0.0.1/test-frontend-redirect-uri");

        assertEquals(authenticationMap, response);
    }

    @Test
    void testCompleteAuthenticationExistingUserSessionSuccess() throws SpotifyAPIException {
        SpotifyToken spotifyToken = mockSpotifyAPIAuthenticate();

        when(webConfig.getFrontendRedirectUri()).thenReturn("http://127.0.0.1/test-frontend-redirect-uri");
        when(jwtUtil.getUserIdFromToken(anyString())).thenReturn("test-user-id");

        when(userService.getUserBySpotifyUserId(anyString())).thenReturn(Optional.of(new User()));
        doNothing().when(userService).updateUserTokens(any(User.class), eq(spotifyToken));

        Map<String, String> response = authService.completeAuthentication("spotify-auth-code", "test-jwt");

        Map<String, String> authenticationMap = new HashMap<>();
        authenticationMap.put("jwt", "test-jwt");
        authenticationMap.put("redirectUri", "http://127.0.0.1/test-frontend-redirect-uri");

        assertEquals(authenticationMap, response);
    }

    @Test
    void testCompleteAuthenticationFailureNoUserReturnedFromSpotify() throws SpotifyAPIException {

        mockSpotifyAPIAuthenticate();
        when(webConfig.getFrontendRedirectUri()).thenReturn("http://127.0.0.1/test-frontend-redirect-uri");
        when(jwtUtil.getUserIdFromToken(anyString())).thenReturn("");

        when(spotifyAPIService.fetchUserDetails(any(String.class))).thenThrow(new SpotifyAPIException("No User Returned from Spotify"));

        Map<String, String> response = authService.completeAuthentication("spotify-auth-code", "test-jwt");

        assertTrue(response.isEmpty());
    }

    @Test
    void testCompleteAuthenticationFailureNoSessionFoundForExistingUser() throws SpotifyAPIException {

        mockSpotifyAPIAuthenticate();

        when(webConfig.getFrontendRedirectUri()).thenReturn("http://127.0.0.1/test-frontend-redirect-uri");
        when(jwtUtil.getUserIdFromToken(anyString())).thenReturn("test-user-id");

        when(userService.getUserBySpotifyUserId(anyString())).thenReturn(Optional.empty());

        Map<String, String> response = authService.completeAuthentication("spotify-auth-code", "test-jwt");

        assertTrue(response.isEmpty());
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