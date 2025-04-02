package com.tough.jukebox.authentication.service;

import com.tough.jukebox.authentication.config.SpotifyConfig;
import com.tough.jukebox.authentication.config.WebConfig;
import com.tough.jukebox.authentication.model.SpotifyToken;
import com.tough.jukebox.authentication.model.User;
import com.tough.jukebox.authentication.security.JwtUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.scheduling.annotation.Scheduled;

import java.time.Duration;
import java.time.Instant;
import java.util.*;

// TODO: unhappy paths to be added (and wired through to controller)
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
        SpotifyToken spotifyToken = spotifyAPIService.authenticate(spotifyAuthCode);

        String jwt = checkAndCreateUser(spotifyToken, incomingJwt);

        Map<String, String> authenticationMap = new HashMap<>();
        authenticationMap.put("jwt", jwt);
        authenticationMap.put("redirectUri", webConfig.getFrontendRedirectUri());

        return authenticationMap;
    }

    public boolean logOut(String jwt) {
        String spotifyUserId = jwtUtil.getUserIdFromToken(jwt);

        if (spotifyUserId.isEmpty()) {
            LOGGER.error("Unable to extract user from jwt");
            return false;
        }

        return userService.clearUserTokens(spotifyUserId);
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
        SpotifyToken spotifyToken = spotifyAPIService.refreshAccessToken(user.getSpotifyToken().getRefreshToken());

        userService.updateUserTokens(user, spotifyToken);
    }

    private String checkAndCreateUser(SpotifyToken newSpotifyToken, String jwtToken) {

        String spotifyUserId = jwtUtil.getUserIdFromToken(jwtToken);

        if (spotifyUserId.isEmpty()) {
            LOGGER.info("No session exists for user");
            User user = spotifyAPIService.fetchUserDetails(newSpotifyToken.getAccessToken());

            if (user != null) {
                LOGGER.info("User returned from Spotify: {}", user.getSpotifyUserId());
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
                LOGGER.error("No user returned from Spotify");
            }
        } else {
            userService.getUserBySpotifyUserId(spotifyUserId).ifPresent(userEntity -> {
                userService.updateUserTokens(userEntity, newSpotifyToken);
            });
            LOGGER.info("Session exists for user: {}", spotifyUserId);
        }
        return jwtToken;
    }
}