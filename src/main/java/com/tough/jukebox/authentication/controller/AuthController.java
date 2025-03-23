package com.tough.jukebox.authentication.controller;

import com.tough.jukebox.authentication.service.AuthService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    private final AuthService authService;

    @Autowired
    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @GetMapping("/auth/spotifyRedirectParams")
    public ResponseEntity<Map<String, String>> getSpotifyRedirectParams() {

        logger.info("/auth/spotifyRedirectParams request received");

        Map<String, String> params = authService.getSpotifyRedirectParams();

        return ResponseEntity.status(HttpStatus.OK)
                .body(params);
    }

    @GetMapping("auth/spotifyAuthorizationCallback")
    public ResponseEntity<Void> exchangeAuthCodeForSpotifyToken(@RequestParam String code) {

        logger.info("/auth/spotifyAuthorizationCallback request received");

        String redirectUri = authService.exchangeAuthCodeForSpotifyToken(code);

        return ResponseEntity.status(HttpStatus.SEE_OTHER)
                .header(HttpHeaders.LOCATION, redirectUri)
                .build();
    }

    @GetMapping("auth/token")
    public ResponseEntity<Map<String, String>> getSpotifyAccessToken() {
        logger.info("/auth/token request received");

        Map<String, String> response = authService.getSpotifyAccessToken();

        return ResponseEntity.status(HttpStatus.OK)
                .body(response);
    }
}
