package com.tough.jukebox.authentication.controller;

import com.tough.jukebox.authentication.exception.SpotifyAPIException;
import com.tough.jukebox.authentication.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.time.Duration;
import java.util.Map;

@RestController
public class AuthController {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthController.class);

    private static final String JWT_LABEL = "jwt";
    private static final String REDIRECT_URI_LABEL = "redirectUri";

    private final AuthService authService;

    @Autowired
    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @GetMapping("auth/spotifyRedirectParams")
    public ResponseEntity<Map<String, String>> getSpotifyRedirectParams() {
        LOGGER.info("/auth/spotifyRedirectParams request received");

        Map<String, String> params = authService.getSpotifyRedirectParams();

        if (params != null && !params.isEmpty()) {
            return ResponseEntity.status(HttpStatus.OK).contentType(MediaType.APPLICATION_JSON).body(params);
        } else {
            LOGGER.error("Spotify params Not Found (404)");
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
    }

    @GetMapping("auth/spotifyAuthorizationCallback")
    public ResponseEntity<Void> authenticate(@RequestParam String code, HttpServletRequest request) {

        LOGGER.info("/auth/spotifyAuthorizationCallback request received");

        try {
            Map<String, String> authenticationMap = authService.completeAuthentication(code);

            ResponseCookie cookie = ResponseCookie.from(JWT_LABEL, authenticationMap.get(JWT_LABEL))
                    .httpOnly(true)
                    .secure(false)
                    .path("/")
                    .maxAge(Duration.ofHours(1))
                    .build();

            return ResponseEntity.status(HttpStatus.SEE_OTHER)
                    .header(HttpHeaders.LOCATION, authenticationMap.get(REDIRECT_URI_LABEL))
                    .header(HttpHeaders.SET_COOKIE, cookie.toString())
                    .build();
        } catch(SpotifyAPIException spotifyAPIException) {
            LOGGER.error("Internal Server Error (500): {}", spotifyAPIException.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        } catch(NoSuchAlgorithmException | InvalidKeySpecException exception) {
            LOGGER.error("Unauthorized (401): {}", exception.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }

    @GetMapping("auth/loginCheck")
    public ResponseEntity<Void> loginCheck(HttpServletRequest request) {
        LOGGER.info("/auth/loginCheck request received");
        return ResponseEntity.status(HttpStatus.OK).build();
    }

    @PostMapping("auth/logout")
    public ResponseEntity<Void> logout(HttpServletResponse response, HttpServletRequest request) {
        LOGGER.info("/auth/logout request received");

        boolean userLogoutSuccess = authService.logOut((String)request.getAttribute(JWT_LABEL));

        ResponseCookie cookie = ResponseCookie.from(JWT_LABEL)
                .httpOnly(true)
                .secure(false)
                .path("/")
                .maxAge(Duration.ZERO)
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());

        return ResponseEntity.status(userLogoutSuccess ? HttpStatus.OK : HttpStatus.NOT_FOUND).build();
    }
}