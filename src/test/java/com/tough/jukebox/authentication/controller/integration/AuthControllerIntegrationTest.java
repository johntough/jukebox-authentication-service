package com.tough.jukebox.authentication.controller.integration;

import com.tough.jukebox.authentication.controller.AuthController;
import com.tough.jukebox.authentication.exception.SpotifyAPIException;
import com.tough.jukebox.authentication.security.JwtUtil;
import com.tough.jukebox.authentication.service.AuthService;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;

@WebMvcTest(controllers = AuthController.class)
class AuthControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private AuthService authService;

    @MockitoBean
    JwtUtil jwtUtil;

    @Test
    void testGetSpotifyRedirectParamsSuccess() throws Exception {
        when(authService.getSpotifyRedirectParams()).thenReturn(Map.of(
                "clientId", "test-client-id",
                "redirectUri", "http://test-redirect-uri"
        ));

        mockMvc.perform(get("/auth/spotifyRedirectParams"))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(content().json("{\"clientId\":\"test-client-id\",\"redirectUri\":\"http://test-redirect-uri\"}"));
    }

    @Test
    void testGetSpotifyRedirectParamsFailureNotFound404() throws Exception {
        when(authService.getSpotifyRedirectParams()).thenReturn(null);

        mockMvc.perform(get("/auth/spotifyRedirectParams"))
                .andExpect(status().isNotFound());
    }

    @Test
    void testLoginCheckSuccess() throws Exception {
        when(jwtUtil.validateToken(anyString())).thenReturn(true);

        mockMvc.perform(get("/auth/loginCheck")
                .cookie(new Cookie("jwt", "mock-jwt-value")))
                .andExpect(status().isOk());
    }

    @Test
    void testLoginCheckFailureInvalidToken401() throws Exception {
        mockMvc.perform(get("/auth/loginCheck")
                 .cookie(new Cookie("jwt", "mock-jwt-value")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void testLogoutSuccess() throws Exception {
        when(jwtUtil.validateToken(anyString())).thenReturn(true);
        when(authService.logOut(anyString())).thenReturn(true);

        mockMvc.perform(post("/auth/logout")
                .cookie(new Cookie("jwt", "mock-jwt-value")))
                .andExpect(status().isOk());
    }

    @Test
    void testLogoutFailureInvalidToken401() throws Exception {
        mockMvc.perform(post("/auth/logout")
                .cookie(new Cookie("jwt", "mock-jwt-value")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void testLogoutFailureNoValidUser404() throws Exception {
        when(jwtUtil.validateToken(anyString())).thenReturn(true);
        when(authService.logOut(anyString())).thenReturn(false);

        mockMvc.perform(post("/auth/logout")
                .cookie(new Cookie("jwt", "mock-jwt-value")))
                .andExpect(status().isNotFound());
    }

    @Test
    void testSpotifyAuthorizationCallbackSuccess() throws Exception {
        when(jwtUtil.validateToken(anyString())).thenReturn(true);
        when(authService.completeAuthentication(
                anyString()
        )).thenReturn(Map.of("redirectUri", "http://test-redirect-uri", "jwt", "test-jwt-value"));

        mockMvc.perform(get("/auth/spotifyAuthorizationCallback")
                .param("code", "test-code")
                .cookie(new Cookie("jwt", "mock-jwt-value")))
                .andExpect(status().isSeeOther())
                .andExpect(header().exists(HttpHeaders.LOCATION))
                .andExpect(header().exists(HttpHeaders.SET_COOKIE));
    }

    @Test
    void testSpotifyAuthorizationCallbackFailureSpotifyAPIException() throws Exception {
        when(jwtUtil.validateToken(anyString())).thenReturn(true);
        when(authService.completeAuthentication(
                anyString()
        )).thenThrow(new SpotifyAPIException("Spotify API Exception"));

        mockMvc.perform(get("/auth/spotifyAuthorizationCallback")
                        .param("code", "test-code")
                        .cookie(new Cookie("jwt", "mock-jwt-value")))
                .andExpect(status().isInternalServerError())
                .andExpect(header().doesNotExist(HttpHeaders.SET_COOKIE));
    }

    @Test
    void testSpotifyAuthorizationCallbackFailureNoSuchAlgorithmException() throws Exception {
        when(jwtUtil.validateToken(anyString())).thenReturn(true);
        when(authService.completeAuthentication(
                anyString()
        )).thenThrow(new NoSuchAlgorithmException("Spotify API Exception"));

        mockMvc.perform(get("/auth/spotifyAuthorizationCallback")
                        .param("code", "test-code")
                        .cookie(new Cookie("jwt", "mock-jwt-value")))
                .andExpect(status().isUnauthorized())
                .andExpect(header().doesNotExist(HttpHeaders.SET_COOKIE));
    }

    @Test
    void testSpotifyAuthorizationCallbackFailureInvalidKeySpecException() throws Exception {
        when(jwtUtil.validateToken(anyString())).thenReturn(true);
        when(authService.completeAuthentication(
                anyString()
        )).thenThrow(new InvalidKeySpecException("Spotify API Exception"));

        mockMvc.perform(get("/auth/spotifyAuthorizationCallback")
                        .param("code", "test-code")
                        .cookie(new Cookie("jwt", "mock-jwt-value")))
                .andExpect(status().isUnauthorized())
                .andExpect(header().doesNotExist(HttpHeaders.SET_COOKIE));
    }

    @Test
    void testSpotifyAuthorizationCallbackFailureBadRequest400() throws Exception {
        mockMvc.perform(get("/auth/spotifyAuthorizationCallback")
                .cookie(new Cookie("jwt", "mock-jwt-value")))
                .andExpect(status().isBadRequest())
                .andExpect(header().doesNotExist(HttpHeaders.SET_COOKIE));
    }
}