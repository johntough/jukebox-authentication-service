package com.tough.jukebox.authentication.service;

import com.tough.jukebox.authentication.config.SpotifyConfig;
import com.tough.jukebox.authentication.config.WebConfig;
import com.tough.jukebox.authentication.exception.SpotifyAPIException;
import com.tough.jukebox.authentication.exception.UserSessionException;
import com.tough.jukebox.authentication.model.SpotifyToken;
import com.tough.jukebox.authentication.model.User;
import com.tough.jukebox.authentication.security.JwtUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.scheduling.annotation.Scheduled;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

@Service
public class AuthService {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthService.class);

    private final SpotifyConfig spotifyConfig;
    private final WebConfig webConfig;
    private final UserService userService;
    private final SpotifyAPIService spotifyAPIService;
    private final JwtUtil jwtUtil;

    @Autowired
    public AuthService(SpotifyConfig spotifyConfig, WebConfig webConfig, UserService userService, SpotifyAPIService spotifyAPIService, JwtUtil jwtUtil) {
        this.spotifyConfig = spotifyConfig;
        this.webConfig = webConfig;
        this.userService = userService;
        this.spotifyAPIService = spotifyAPIService;
        this.jwtUtil = jwtUtil;
    }

    public Map<String, String> getSpotifyRedirectParams() {
        return Map.of(
                "clientId", spotifyConfig.getSpotifyAppClientId(),
                "redirectUri", spotifyConfig.getSpotifyRedirectUri()
        );
    }

    public Map<String, String> completeAuthentication(String spotifyAuthCode, String incomingJwt) {

        try {
            Map<String, String> authenticationMap = new HashMap<>();
            authenticationMap.put("redirectUri", webConfig.getFrontendRedirectUri());
            authenticationMap.put("jwt", checkAndCreateUser(
                    spotifyAPIService.authenticate(spotifyAuthCode),
                    incomingJwt)
            );
            return authenticationMap;
        } catch (SpotifyAPIException | UserSessionException | NoSuchAlgorithmException | InvalidKeySpecException exception) {
            LOGGER.error(exception.getMessage());
            return new HashMap<>();
        }
    }

    public boolean logOut(String jwt) {
        try {
            String spotifyUserId = jwtUtil.getUserIdFromToken(jwt);

            if (spotifyUserId.isEmpty()) {
                LOGGER.error("Unable to extract user from jwt");
                return false;
            }
            return userService.clearUserTokens(spotifyUserId);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            LOGGER.error("Error when extracting user from jwt: {}", e.getMessage());
            return false;
        }
    }

    @Scheduled(fixedRate = 180000)  // Runs every 3 minutes
    private void checkTokenRefresh() {
        LOGGER.info("Checking database for access tokens expiring soon");

        List<User> userList = userService.getUsersWithExpiringTokens(
                Instant.now(),
                Instant.now().plus(Duration.ofMinutes(5))
        );

        for (User user : userList) {
            LOGGER.info("Access token expiring soon for user: {}", user.getSpotifyUserId());
            refreshAccessToken(user);
        }
    }

    private void refreshAccessToken(User user) {
        try {
            SpotifyToken spotifyToken = spotifyAPIService.refreshAccessToken(user.getSpotifyToken().getRefreshToken());
            userService.updateUserTokens(user, spotifyToken);
        } catch (SpotifyAPIException exception) {
            LOGGER.error(exception.getMessage());
        }
    }

    private String checkAndCreateUser(SpotifyToken newSpotifyToken, String jwtToken) throws SpotifyAPIException, UserSessionException, NoSuchAlgorithmException, InvalidKeySpecException {

        String spotifyUserId = jwtUtil.getUserIdFromToken(jwtToken);

        if (spotifyUserId.isEmpty()) {
            LOGGER.info("No session exists for user");
            User user = spotifyAPIService.fetchUserDetails(newSpotifyToken.getAccessToken());

            // check if user exists in database (i.e. has previously logged in) and update
            userService.getUserBySpotifyUserId(user.getSpotifyUserId()).ifPresentOrElse(
                    userEntity -> {
                        userService.updateUserTokens(userEntity, newSpotifyToken);
                        LOGGER.info("New access tokens created for existing user: {}.", userEntity.getSpotifyUserId());
                    }, () -> {
                        userService.updateUserTokens(user, newSpotifyToken);
                        LOGGER.info("New user profile (and access tokens) created for user: {}.", user.getSpotifyUserId());
                    }
            );
            return jwtUtil.createToken(user.getSpotifyUserId());
        } else {
            User userEntity = userService.getUserBySpotifyUserId(spotifyUserId).orElseThrow(() -> new UserSessionException("No user returned from Spotify"));
            userService.updateUserTokens(userEntity, newSpotifyToken);
            LOGGER.info("Session exists for user: {}", spotifyUserId);
        }
        return jwtToken;
    }
}