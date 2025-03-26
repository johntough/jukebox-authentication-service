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

import java.util.*;

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

    private boolean tokenRefreshProcessEnabled = false;

    private final RestTemplate restTemplate;
    private final SpotifyConfig spotifyConfig;
    private final WebConfig webConfig;

    private final UserRepository userRepository;

    private final JwtUtil jwtUtil;

    // TODO: to be replaced with JWT
    private String spotifyUserId = "";

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

    // TODO: unhappy path to be added (and wired through to controller)
    public String authenticateWithSpotify(String authCode, String jwtToken) {

        MultiValueMap<String, String> requestBodyMap = new LinkedMultiValueMap<>();
        requestBodyMap.add(REDIRECT_URI_NAME, spotifyConfig.getSpotifyRedirectUri());
        requestBodyMap.add(GRANT_TYPE_NAME, AUTHORIZATION_CODE_NAME);
        requestBodyMap.add(SPOTIFY_RESPONSE_TYPE_CODE, authCode);

        return requestAccessTokenFromSpotify(requestBodyMap, jwtToken);
    }

    // TODO: handle refresh of access tokens correctly with database
//    @Scheduled(fixedRate = 60000)  // Runs every minute
//    private void checkTokenRefresh() {
//        if (tokenRefreshProcessEnabled) {
//            if (expiresIn <= 300) { // 5 minutes
//                refreshAccessToken();
//            } else {
//                expiresIn = expiresIn - 60;
//            }
//        }
//    }
//
//    private void refreshAccessToken() {
//        logger.info("Initiating token refresh process");
//
//        userRepository.findBySpotifyUserId(spotifyUserId).ifPresent(user -> {
//
//            MultiValueMap<String, String> requestBodyMap = new LinkedMultiValueMap<>();
//            requestBodyMap.add(GRANT_TYPE_NAME, REFRESH_TOKEN_NAME);
//            requestBodyMap.add(REFRESH_TOKEN_NAME, user.getSpotifyToken().getRefreshToken());
//
//            requestAccessTokenFromSpotify(requestBodyMap);
//        });
//    }

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

                // TODO: calculate tokenExpiry correctly and incorporate into database
                int expiresIn = (int) responseBody.get(EXPIRES_IN_NAME);
                logger.info("expiresIn: {}", expiresIn);
                Date tokenExpiry = new Date(System.currentTimeMillis() + (long)expiresIn * 1000);
                logger.info("Access token tokenExpiry: {}", tokenExpiry);
                tokenRefreshProcessEnabled = true;

                jwt = checkAndCreateUser(accessToken, refreshToken, jwtToken);
            }
        }

        return jwt;
    }

    private String checkAndCreateUser(String accessToken, String refreshToken, String jwtToken) {

        String spotifyUserId = jwtUtil.getUserIdFromToken(jwtToken);
        logger.info("spotifyUserId extracted from jwt: {}", spotifyUserId);
        if (spotifyUserId.isEmpty()) {
            logger.info("First time login. User does not exist");
            User user = fetchSpotifyUserDetails(accessToken);

            if (user != null) {
                logger.info("User {} returned from Spotify. User details will now be saved.", user.getDisplayName());
                saveUserEntity(user, accessToken, refreshToken);
                return jwtUtil.createToken(user.getSpotifyUserId());
            } else {
                logger.error("No user returned from Spotify");
            }
        } else {
            logger.info("User {} exists", spotifyUserId);
            userRepository.findBySpotifyUserId(spotifyUserId).ifPresent(user -> {
                saveUserEntity(user, accessToken, refreshToken);
            });
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
                spotifyUserId = (String) responseBody.get("id");
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

    private void saveUserEntity(User user, String accessToken, String refreshToken) {

        SpotifyToken spotifyToken = new SpotifyToken();
        spotifyToken.setAccessToken(accessToken);

        logger.info("Spotify access token: {}", accessToken);

        if (!refreshToken.isEmpty()) {
            spotifyToken.setRefreshToken(refreshToken);
        }

        user.setSpotifyToken(spotifyToken);

        User userEntity = userRepository.save(user);
        logger.info("User updated: {}:", userEntity.getDisplayName());
    }
}