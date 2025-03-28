package com.tough.jukebox.authentication.service;

import com.tough.jukebox.authentication.config.SpotifyConfig;
import com.tough.jukebox.authentication.config.WebConfig;
import com.tough.jukebox.authentication.model.SpotifyToken;
import com.tough.jukebox.authentication.model.User;
import com.tough.jukebox.authentication.repository.UserRepository;
import com.tough.jukebox.authentication.util.JwtUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.scheduling.annotation.Scheduled;

import java.time.Duration;
import java.time.Instant;
import java.util.*;

// TODO: unhappy paths to be added (and wired through to controller)
@Service
public class AuthService {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthService.class);

    public static final String ACCESS_TOKEN_NAME = "access_token";
    public static final String REFRESH_TOKEN_NAME = "refresh_token";
    public static final String AUTHORIZATION_CODE_NAME = "authorization_code";
    public static final String GRANT_TYPE_NAME = "grant_type";
    public static final String REDIRECT_URI_NAME = "redirect_uri";
    public static final String EXPIRES_IN_NAME = "expires_in";
    public static final String TOKEN_EXPIRY_NAME = "token_expiry";
    public static final String SPOTIFY_RESPONSE_TYPE_CODE = "code";

    private final RestTemplate restTemplate;
    private final SpotifyConfig spotifyConfig;
    private final WebConfig webConfig;
    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;

    @Autowired
    public AuthService(RestTemplate restTemplate, SpotifyConfig serviceConfig, WebConfig webConfig, UserRepository userRepository, JwtUtil jwtUtil) {
        this.restTemplate = restTemplate;
        this.spotifyConfig = serviceConfig;
        this.webConfig = webConfig;
        this.userRepository = userRepository;
        this.jwtUtil = jwtUtil;
    }

    public Map<String, String> getSpotifyRedirectParams() {
        Map<String, String> responseMap = new HashMap<>();
        responseMap.put("clientId", spotifyConfig.getSpotifyAppClientId());
        responseMap.put("redirectUri", spotifyConfig.getSpotifyRedirectUri());

        return responseMap;
    }

    public Map<String, String> completeAuthentication(String spotifyAuthCode, String jwtToken) {
        String jwt = authenticateWithSpotify(spotifyAuthCode, jwtToken);
        String redirectUri = webConfig.getFrontendRedirectUri();

        Map<String, String> authenticationMap = new HashMap<>();
        authenticationMap.put("jwt", jwt);
        authenticationMap.put("redirectUri", redirectUri);

        return authenticationMap;
    }

    public void logout(String jwt) {
        String spotifyUserId = jwtUtil.getUserIdFromToken(jwt);

        if (!spotifyUserId.isEmpty()) {
            clearSpotifyTokens(spotifyUserId);
        } else {
            LOGGER.error("Unable to extract user from jwt");
        }
    }

    @Scheduled(fixedRate = 180000)  // Runs every 3 minutes
    private void checkTokenRefresh() {
        LOGGER.info("Checking database for access tokens expiring soon");

        List<User> userList = userRepository.findUsersWithSpotifyTokenExpiringSoon(
                Instant.now(),
                Instant.now().plus(Duration.ofMinutes(5))
        );

        for (User user : userList) {
            LOGGER.info("Access token expiring soon for user: {}", user.getSpotifyUserId());
            refreshAccessToken(user);
        }
    }

    private void refreshAccessToken(User user) {
        MultiValueMap<String, String> requestBodyMap = new LinkedMultiValueMap<>();
        requestBodyMap.add(GRANT_TYPE_NAME, REFRESH_TOKEN_NAME);
        requestBodyMap.add(REFRESH_TOKEN_NAME, user.getSpotifyToken().getRefreshToken());

        Map<String, Object> tokenData = requestAccessTokenFromSpotify(requestBodyMap);

        saveUserEntity(
                user,
                (String)tokenData.get(ACCESS_TOKEN_NAME),
                (String)tokenData.get(REFRESH_TOKEN_NAME),
                (Instant)tokenData.get(TOKEN_EXPIRY_NAME)
        );
    }

    private String authenticateWithSpotify(String authCode, String jwtToken) {

        MultiValueMap<String, String> requestBodyMap = new LinkedMultiValueMap<>();
        requestBodyMap.add(REDIRECT_URI_NAME, spotifyConfig.getSpotifyRedirectUri());
        requestBodyMap.add(GRANT_TYPE_NAME, AUTHORIZATION_CODE_NAME);
        requestBodyMap.add(SPOTIFY_RESPONSE_TYPE_CODE, authCode);

        return createSpotifyTokensAndUser(requestBodyMap, jwtToken);
    }

    private Map<String, Object> requestAccessTokenFromSpotify(MultiValueMap<String, String> requestBodyMap) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setBasicAuth(Base64.getEncoder().encodeToString((spotifyConfig.getSpotifyAppClientId() + ":" + spotifyConfig.getSpotifyAppClientSecret()).getBytes()));

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(requestBodyMap, headers);

        ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                spotifyConfig.getSpotifyTokenUri(),
                HttpMethod.POST,
                request,
                new ParameterizedTypeReference<>() {
                }
        );

        Map<String, Object> tokenData = new HashMap<>();

        if (response.getStatusCode().is2xxSuccessful()) {
            Map<String, Object> responseBody = response.getBody();

            if (responseBody != null) {
                String accessToken = (String) responseBody.get(ACCESS_TOKEN_NAME);
                String refreshToken = (String) responseBody.get(REFRESH_TOKEN_NAME);

                int expiresIn = (int) responseBody.get(EXPIRES_IN_NAME);
                Instant tokenExpiry = Instant.now().plusSeconds(expiresIn);

                tokenData.put(ACCESS_TOKEN_NAME, accessToken);
                tokenData.put(REFRESH_TOKEN_NAME, (refreshToken == null ? "" : refreshToken));
                tokenData.put(TOKEN_EXPIRY_NAME, tokenExpiry);
            }
        }

        return tokenData;
    }

    private String createSpotifyTokensAndUser(MultiValueMap<String, String> requestBodyMap, String jwtToken) {
        Map<String, Object> tokenData = requestAccessTokenFromSpotify(requestBodyMap);

        return checkAndCreateUser(
                (String)tokenData.get(ACCESS_TOKEN_NAME),
                (String)tokenData.get(REFRESH_TOKEN_NAME),
                (Instant)tokenData.get(TOKEN_EXPIRY_NAME),
                jwtToken
        );
    }

    private String checkAndCreateUser(String accessToken, String refreshToken, Instant tokenExpiry, String jwtToken) {

        String spotifyUserId = jwtUtil.getUserIdFromToken(jwtToken);

        if (spotifyUserId.isEmpty()) {
            LOGGER.info("No session exists for user");
            User user = fetchSpotifyUserDetails(accessToken);

            if (user != null) {
                LOGGER.info("User returned from Spotify: {}", user.getSpotifyUserId());

                // TODO: up to here in unit test
                // check if user exists in database (i.e. has previously logged in) and update
                userRepository.findBySpotifyUserId(user.getSpotifyUserId()).ifPresentOrElse(
                        userEntity -> {
                            saveUserEntity(userEntity, accessToken, refreshToken, tokenExpiry);
                            LOGGER.info("New access tokens created for existing user: {}.", userEntity.getSpotifyUserId());
                        }, () -> {
                            saveUserEntity(user, accessToken, refreshToken, tokenExpiry);
                            LOGGER.info("New user profile (and access tokens) created for user: {}.", user.getSpotifyUserId());
                        }
                );

                return jwtUtil.createToken(user.getSpotifyUserId());
            } else {
                LOGGER.error("No user returned from Spotify");
            }
        } else {
            userRepository.findBySpotifyUserId(spotifyUserId).ifPresent(userEntity -> {
                saveUserEntity(userEntity, accessToken, refreshToken, tokenExpiry);
            });
            LOGGER.info("Session exists for user: {}", spotifyUserId);
        }
        return jwtToken;
    }

    private User fetchSpotifyUserDetails(String accessToken) {

        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<String> request = new HttpEntity<>(headers);

        ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                spotifyConfig.getSpotifyCurrentUserUri(),
                HttpMethod.GET,
                request,
                new ParameterizedTypeReference<>() {}
        );

        if (response.getStatusCode().is2xxSuccessful()) {
            Map<String, Object> responseBody = response.getBody();

            if (responseBody != null) {
                String spotifyUserId = (String) responseBody.get("id");
                String email = (String) responseBody.get("email");
                String displayName = (String) responseBody.get("display_name");

                User user = new User();
                user.setSpotifyUserId(spotifyUserId);
                user.setDisplayName(displayName);
                user.setEmailAddress(email);
                return user;
            }
        }

        return null;
    }

    private void clearSpotifyTokens(String spotifyUserId) {
        userRepository.findBySpotifyUserId(spotifyUserId).ifPresent(user -> {
            user.setSpotifyToken(null);
            User userEntity = userRepository.save(user);
            LOGGER.info("User's Spotify tokens cleared: {}", userEntity.getDisplayName());
        });
    }

    private void saveUserEntity(User user, String accessToken, String refreshToken, Instant tokenExpiry) {

        SpotifyToken spotifyToken = user.getSpotifyToken();

        if (spotifyToken != null) {
            spotifyToken.setAccessToken(accessToken);
            spotifyToken.setTokenExpiry(tokenExpiry);

            if (!refreshToken.isEmpty()) {
                spotifyToken.setRefreshToken(refreshToken);
            }
        } else {
            spotifyToken = new SpotifyToken();
            spotifyToken.setAccessToken(accessToken);
            spotifyToken.setTokenExpiry(tokenExpiry);
            spotifyToken.setRefreshToken(refreshToken);
            user.setSpotifyToken(spotifyToken);
        }

        userRepository.save(user);
        LOGGER.info("Spotify access token updated for user: {}. Token valid until: {}", user.getSpotifyUserId(), tokenExpiry);
    }
}