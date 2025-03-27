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

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    public static final String ACCESS_TOKEN_NAME = "access_token";
    public static final String REFRESH_TOKEN_NAME = "refresh_token";
    public static final String AUTHORIZATION_CODE_NAME = "authorization_code";
    public static final String GRANT_TYPE_NAME = "grant_type";
    public static final String REDIRECT_URI_NAME = "redirect_uri";
    public static final String EXPIRES_IN_NAME = "expires_in";
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

    public String authenticateWithSpotify(String authCode, String jwtToken) {

        MultiValueMap<String, String> requestBodyMap = new LinkedMultiValueMap<>();
        requestBodyMap.add(REDIRECT_URI_NAME, spotifyConfig.getSpotifyRedirectUri());
        requestBodyMap.add(GRANT_TYPE_NAME, AUTHORIZATION_CODE_NAME);
        requestBodyMap.add(SPOTIFY_RESPONSE_TYPE_CODE, authCode);

        return requestAccessTokenFromSpotify(requestBodyMap, jwtToken);
    }

    public void logout(String jwt) {
        String spotifyUserId = jwtUtil.getUserIdFromToken(jwt);

        if (!spotifyUserId.isEmpty()) {
            clearSpotifyTokens(spotifyUserId);
        } else {
            logger.error("Unable to extract user from jwt");
        }
    }

    // TODO: handle refresh of access tokens correctly with database
    @Scheduled(fixedRate = 180000)  // Runs every 3 minutes
    private void checkTokenRefresh() {
        logger.info("Token refresh loop initiated");
        userRepository.findAll().forEach(userEntity -> {
            SpotifyToken token = userEntity.getSpotifyToken();

            if (token != null) {
                logger.info("Checking access token expiry for User: {}", userEntity.getSpotifyUserId());
                Duration duration = Duration.between(token.getTokenExpiry(), Instant.now());
                if (duration.abs().toMinutes() <= 5) {
                    logger.info("Access token needs refreshing for User: {}", userEntity.getSpotifyUserId());
                    //refreshAccessToken(userEntity);
                }
            }
        });
    }

    // TODO: figure out a way of performing the Spotify token refresh without the need for jwt, as per current logic (as this is internally triggered)
    private void refreshAccessToken(User user) {
        logger.info("Initiating token refresh process");

        MultiValueMap<String, String> requestBodyMap = new LinkedMultiValueMap<>();
        requestBodyMap.add(GRANT_TYPE_NAME, REFRESH_TOKEN_NAME);
        requestBodyMap.add(REFRESH_TOKEN_NAME, user.getSpotifyToken().getRefreshToken());

        requestAccessTokenFromSpotify(requestBodyMap, null);

    }

    private String requestAccessTokenFromSpotify(MultiValueMap<String, String> requestBodyMap, String jwtToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setBasicAuth(Base64.getEncoder().encodeToString((spotifyConfig.getSpotifyAppClientId() + ":" + spotifyConfig.getSpotifyAppClientSecret()).getBytes()));

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(requestBodyMap, headers);

        ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                spotifyConfig.getSpotifyTokenUri(),
                HttpMethod.POST,
                request,
                new ParameterizedTypeReference<>() {}
        );

        String jwt = "";

        if (response.getStatusCode().is2xxSuccessful()) {

            Map<String, Object> responseBody = response.getBody();

            if (responseBody != null) {
                String accessToken = (String) responseBody.get(ACCESS_TOKEN_NAME);
                String refreshToken = (String) responseBody.get(REFRESH_TOKEN_NAME);

                int expiresIn = (int) responseBody.get(EXPIRES_IN_NAME);
                Instant tokenExpiry = Instant.now().plusSeconds(expiresIn);

                jwt = checkAndCreateUser(accessToken, refreshToken, tokenExpiry, jwtToken);
            }
        }

        return jwt;
    }

    private String checkAndCreateUser(String accessToken, String refreshToken, Instant tokenExpiry, String jwtToken) {

        String spotifyUserId = jwtUtil.getUserIdFromToken(jwtToken);

        if (spotifyUserId.isEmpty()) {
            logger.info("No session exists for User");
            User user = fetchSpotifyUserDetails(accessToken);

            if (user != null) {
                logger.info("User {} returned from Spotify.", user.getSpotifyUserId());

                // check if user exists in database (i.e. has previously logged in) and update
                userRepository.findBySpotifyUserId(user.getSpotifyUserId()).ifPresentOrElse(
                        userEntity -> {
                            saveUserEntity(userEntity, accessToken, tokenExpiry, refreshToken);
                            logger.info("New access tokens created for existing User: {}.", userEntity.getSpotifyUserId());
                        }, () -> {
                            saveUserEntity(user, accessToken, tokenExpiry, refreshToken);
                            logger.info("New user (and access tokens) created for User: {}.", user.getSpotifyUserId());
                        }
                );

                return jwtUtil.createToken(user.getSpotifyUserId());
            } else {
                logger.error("No user returned from Spotify");
            }
        } else {
            userRepository.findBySpotifyUserId(spotifyUserId).ifPresent(userEntity -> {
                saveUserEntity(userEntity, accessToken, tokenExpiry, refreshToken);
            });
            logger.info("Session exists for User: {}. Access tokens updated.", spotifyUserId);
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
            logger.info("User's Spotify tokens cleared: {}:", userEntity.getDisplayName());
        });
    }

    private void saveUserEntity(User user, String accessToken, Instant tokenExpiry, String refreshToken) {

        SpotifyToken spotifyToken = new SpotifyToken();
        spotifyToken.setAccessToken(accessToken);
        spotifyToken.setTokenExpiry(tokenExpiry);

        logger.info("Spotify access token valid until: {}", tokenExpiry);

        if (!refreshToken.isEmpty()) {
            spotifyToken.setRefreshToken(refreshToken);
        }

        user.setSpotifyToken(spotifyToken);

        userRepository.save(user);
    }
}