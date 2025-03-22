package com.tough.jukebox.authentication.service;

import com.tough.jukebox.authentication.config.SpotifyConfig;
import com.tough.jukebox.authentication.config.WebConfig;
import com.tough.jukebox.authentication.exceptions.VaultFailureException;
import com.tough.jukebox.authentication.model.VaultResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class AuthServiceTest {

    @Mock
    VaultService vaultService;

    @Mock
    SpotifyConfig spotifyConfig;

    @Mock
    WebConfig webConfig;

    @Mock
    private RestTemplate restTemplate;

    @InjectMocks
    AuthService authService;

    @Test
    void testSuccessfulLogin() throws URISyntaxException {

        when(spotifyConfig.getSpotifyAuthorizeUri()).thenReturn("https://testuri/authorize/");
        when(spotifyConfig.getSpotifyAppClientId()).thenReturn("test-client-id");
        when(spotifyConfig.getSpotifyRedirectUri()).thenReturn("test-redirect-uri");

        String redirectUri = authService.returnSpotifyLoginRedirectUri("test-scope");

        assertEquals("{\"redirectUri\":\"https://testuri/authorize/?response_type=code&client_id=test-client-id&scope=test-scope&redirect_uri=test-redirect-uri\"}", redirectUri);
    }

    @Test
    void testSpotifyAuthorizationCallbackSuccessful() throws VaultFailureException {

        when(spotifyConfig.getSpotifyRedirectUri()).thenReturn("http://localhost:8080/spotify");
        when(spotifyConfig.getSpotifyTokenUri()).thenReturn("http://localhost:8080/token");
        when(webConfig.getFrontendRedirectUri()).thenReturn("http://localhost:8080/testFrontEndRedirect");

        Map<String, Object> mockResponse = new HashMap<>();
        mockResponse.put("access_token", "test-access-token");
        mockResponse.put("refresh_token", "test-refresh-token");
        mockResponse.put("expires_in", 360);

        when(restTemplate.postForObject(
                eq("http://localhost:8080/token"),
                any(HttpEntity.class),
                eq(Map.class)
        )).thenReturn(mockResponse);

        when(vaultService.readSecret(
                eq(AuthService.ACCESS_TOKEN_NAME)
        )).thenReturn(new VaultResponse());

        doNothing().when(vaultService).createSecret(
                eq(AuthService.ACCESS_TOKEN_NAME),
                any(Map.class)
        );

        ResponseEntity<Void> response = authService.spotifyAuthorizationCallback("test-auth-code");

        ResponseEntity<Void> expectedResponse = ResponseEntity.status(HttpStatus.FOUND)
                .location(URI.create("http://localhost:8080/testFrontEndRedirect"))
                .build();

        assertEquals(expectedResponse, response);
    }
}