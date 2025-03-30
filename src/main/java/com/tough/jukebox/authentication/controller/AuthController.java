package com.tough.jukebox.authentication.controller;

import com.tough.jukebox.authentication.service.AuthService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
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
    public ResponseEntity<Void> authenticate(@RequestParam String code, HttpServletRequest request) {

        logger.info("/auth/spotifyAuthorizationCallback request received");

        Map<String, String> authenticationMap = authService.completeAuthentication(code, extractJwtFromCookies(request));

        ResponseCookie cookie = ResponseCookie.from("jwt", authenticationMap.get("jwt"))
                .httpOnly(true)
                .secure(false)
                .path("/")
                .maxAge(Duration.ofHours(1))
                .build();

        return ResponseEntity.status(HttpStatus.SEE_OTHER)
                .header(HttpHeaders.LOCATION, authenticationMap.get("redirectUri"))
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .build();
    }

    @GetMapping("auth/loginCheck")
    public ResponseEntity<String> loginCheck(HttpServletRequest request) {
        logger.info("/auth/loginCheck request received");

        if (extractJwtFromCookies(request) != null) {
            return ResponseEntity.status(HttpStatus.OK).body("true");
        } else {
            return ResponseEntity.status(HttpStatus.OK).body("false");
        }
    }

    @PostMapping("auth/logout")
    public ResponseEntity<Void> logout(HttpServletResponse response, HttpServletRequest request) {
        logger.info("/auth/logout request received");

        boolean success = authService.logOut(extractJwtFromCookies(request));

        ResponseCookie cookie = ResponseCookie.from("jwt")
                .httpOnly(true)
                .secure(false)
                .path("/")
                .maxAge(Duration.ZERO)
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());

        // TODO: unhappy path to be added
        return ResponseEntity.status(HttpStatus.OK).build();
    }

    private String extractJwtFromCookies(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();

        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("jwt".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }
}
