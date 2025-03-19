package com.tough.jukebox.authentication.controller;

import com.tough.jukebox.authentication.service.AuthService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.net.URISyntaxException;

@RestController
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    private final AuthService authService;

    @Autowired
    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @GetMapping("/auth/login")
    public String login(@RequestParam String scope) throws URISyntaxException {

        logger.info("/auth/login request received");

        return authService.login(scope);
    }

    @GetMapping("auth/callback")
    public ResponseEntity<Void> callback(@RequestParam String code) {

        logger.info("/auth/callback request received");

        return authService.callback(code);
    }

    @GetMapping("auth/token")
    public String getToken() {
        logger.info("/auth/token request received");

        return authService.getToken();
    }
}
