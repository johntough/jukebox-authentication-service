package com.tough.jukebox.authentication.service;

import com.tough.jukebox.authentication.config.SpotifyConfig;
import com.tough.jukebox.authentication.config.WebConfig;
import com.tough.jukebox.authentication.model.User;
import com.tough.jukebox.authentication.repository.UserRepository;
import com.tough.jukebox.authentication.util.JwtUtil;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    SpotifyConfig spotifyConfig;

    @Mock
    WebConfig webConfig;

    @Mock
    private RestTemplate restTemplate;

    @Mock
    private JwtUtil jwtUtil;

    @Mock
    UserRepository userRepository;

    @InjectMocks
    AuthService authService;

    @Test
    void testReturnSpotifyLoginRedirectUriSuccessful() {
        when(spotifyConfig.getSpotifyAppClientId()).thenReturn("test-client-id");
        when(spotifyConfig.getSpotifyRedirectUri()).thenReturn("test-redirect-uri");

        Map<String, String> params = authService.getSpotifyRedirectParams();

        assertEquals("test-redirect-uri", params.get("redirectUri"));
        assertEquals("test-client-id", params.get("clientId"));
    }

    @Test
    void testLogoutSuccess() {
        when(jwtUtil.getUserIdFromToken("test-user-id")).thenReturn("test-user-id");

        User testUser = new User();
        testUser.setSpotifyUserId("test-user-id");
        testUser.setDisplayName("test-display-name");
        testUser.setEmailAddress("test@email.address");

        when(userRepository.findBySpotifyUserId("test-user-id")).thenReturn(Optional.of(testUser));
        when(userRepository.save(testUser)).thenReturn(testUser);

        authService.logout("test-user-id");

        verify(jwtUtil, times(1)).getUserIdFromToken("test-user-id");
        verify(userRepository, times(1)).findBySpotifyUserId("test-user-id");
        verify(userRepository, times(1)).save(testUser);
    }

    @Test
    void testLogoutFailureEmptyJwt() {
        when(jwtUtil.getUserIdFromToken("")).thenReturn("");

        authService.logout("");

        verify(jwtUtil, times(1)).getUserIdFromToken("");
        verify(userRepository, times(0)).findBySpotifyUserId(anyString());
        verify(userRepository, times(0)).save(any(User.class));
    }

    @Test
    void testCompleteAuthenticationNewUserSuccess() {

        when(spotifyConfig.getSpotifyRedirectUri()).thenReturn("http://127.0.0.1/test-redirect-uri");
        when (spotifyConfig.getSpotifyAppClientId()).thenReturn("test-client-id");
        when(spotifyConfig.getSpotifyAppClientSecret()).thenReturn("test-client-secret");
        when(spotifyConfig.getSpotifyTokenUri()).thenReturn("http://127.0.0.1/test-token-uri");

        Map<String, Object> mockTokenUriResponseMap = new HashMap<>();
        mockTokenUriResponseMap.put("access_token", "test-access-token");
        mockTokenUriResponseMap.put("refresh_token", "test-refresh-token");
        mockTokenUriResponseMap.put("expires_in", 3600);

        when (restTemplate.exchange(
                eq("http://127.0.0.1/test-token-uri"),
                eq(HttpMethod.POST),
                any(HttpEntity.class),
                any(ParameterizedTypeReference.class)
        )).thenReturn(ResponseEntity.ok(mockTokenUriResponseMap));

        when(jwtUtil.getUserIdFromToken("")).thenReturn("");

        when(spotifyConfig.getSpotifyCurrentUserUri()).thenReturn("http://127.0.0.1/test-current-user-uri");

        Map<String, Object> mockCurrentUserUriResponseMap = new HashMap<>();
        mockCurrentUserUriResponseMap.put("id", "test-user-id");
        mockCurrentUserUriResponseMap.put("email", "test@email.address");
        mockCurrentUserUriResponseMap.put("display_name", "test-display-name");

        when (restTemplate.exchange(
                eq("http://127.0.0.1/test-current-user-uri"),
                eq(HttpMethod.GET),
                any(HttpEntity.class),
                any(ParameterizedTypeReference.class)
        )).thenReturn(ResponseEntity.ok(mockCurrentUserUriResponseMap));

        when(userRepository.findBySpotifyUserId("test-user-id")).thenReturn(Optional.empty());
        when(userRepository.save(any(User.class))).thenReturn(new User());

        when(jwtUtil.createToken("test-user-id")).thenReturn("test-jwt");

        when(webConfig.getFrontendRedirectUri()).thenReturn("http://127.0.0.1/test-frontend-redirect-uri");

        Map<String, String> response = authService.completeAuthentication("spotify-auth-code", "");

        Map<String, String> authenticationMap = new HashMap<>();
        authenticationMap.put("jwt", "test-jwt");
        authenticationMap.put("redirectUri", "http://127.0.0.1/test-frontend-redirect-uri");
        assertEquals(authenticationMap, response);
    }

//    @Test
//    void testExchangeAuthCodeForSpotifyTokenSuccessful() throws VaultFailureException {
//
//        when(spotifyConfig.getSpotifyRedirectUri()).thenReturn("http://localhost:8080/spotify");
//        when(spotifyConfig.getSpotifyTokenUri()).thenReturn("http://localhost:8080/token");
//        when(webConfig.getFrontendRedirectUri()).thenReturn("http://localhost:8080/testFrontEndRedirect");
//
//        Map<String, Object> mockResponse = new HashMap<>();
//        mockResponse.put("access_token", "test-access-token");
//        mockResponse.put("refresh_token", "test-refresh-token");
//        mockResponse.put("expires_in", 360);
//
//        when(restTemplate.postForObject(
//                eq("http://localhost:8080/token"),
//                any(HttpEntity.class),
//                eq(Map.class)
//        )).thenReturn(mockResponse);
//
//        when(vaultService.readSecret(
//                AuthService.ACCESS_TOKEN_NAME
//        )).thenReturn(new VaultResponse());
//
//        doNothing().when(vaultService).createSecret(
//                eq(AuthService.ACCESS_TOKEN_NAME),
//                any(Map.class)
//        );
//
//        String redirectUri = authService.exchangeAuthCodeForSpotifyToken("test-auth-code");
//
//        assertEquals("http://localhost:8080/testFrontEndRedirect", redirectUri);
//    }
}