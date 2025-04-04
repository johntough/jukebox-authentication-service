package com.tough.jukebox.authentication.service;

import com.tough.jukebox.authentication.config.SpotifyConfig;
import com.tough.jukebox.authentication.exception.SpotifyAPIException;
import com.tough.jukebox.authentication.model.SpotifyToken;
import com.tough.jukebox.authentication.model.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.time.Instant;
import java.util.Base64;
import java.util.Map;

@Service
public class SpotifyAPIService {

    private static final Logger LOGGER = LoggerFactory.getLogger(SpotifyAPIService.class);

    private static final String ACCESS_TOKEN_LABEL = "access_token";
    private static final String AUTHORIZATION_CODE_LABEL = "authorization_code";
    private static final String EXPIRES_IN_LABEL = "expires_in";
    private static final String GRANT_TYPE_LABEL = "grant_type";
    private static final String REDIRECT_URI_LABEL = "redirect_uri";
    private static final String REFRESH_TOKEN_LABEL = "refresh_token";
    private static final String SPOTIFY_RESPONSE_TYPE_CODE = "code";

    private final RestTemplate restTemplate;
    private final SpotifyConfig spotifyConfig;


    @Autowired
    public SpotifyAPIService(RestTemplate restTemplate, SpotifyConfig spotifyConfig) {
        this.restTemplate = restTemplate;
        this.spotifyConfig = spotifyConfig;
    }

    public SpotifyToken refreshAccessToken(String refreshToken) throws SpotifyAPIException {
        MultiValueMap<String, String> requestBodyMap = new LinkedMultiValueMap<>();
        requestBodyMap.add(GRANT_TYPE_LABEL, REFRESH_TOKEN_LABEL);
        requestBodyMap.add(REFRESH_TOKEN_LABEL, refreshToken);

        return requestAccessToken(requestBodyMap);
    }

    public User fetchUserDetails(String accessToken) throws SpotifyAPIException {

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

        User user = getUserFromSpotifyResponse(response);
        LOGGER.info("User returned from Spotify: {}", user.getSpotifyUserId());
        return user;
    }

    private User getUserFromSpotifyResponse(ResponseEntity<Map<String, Object>> response) throws SpotifyAPIException {
        if (!response.getStatusCode().is2xxSuccessful() || response.getBody() == null) {
            throw new SpotifyAPIException("No User returned from Spotify");
        }

        Map<String, Object> responseBody = response.getBody();
        String spotifyUserId = (String) responseBody.get("id");
        String email = (String) responseBody.get("email");
        String displayName = (String) responseBody.get("display_name");

        User user = new User();
        user.setSpotifyUserId(spotifyUserId);
        user.setDisplayName(displayName);
        user.setEmailAddress(email);
        return user;
    }

    public SpotifyToken authenticate(String authCode) throws SpotifyAPIException {
        MultiValueMap<String, String> requestBodyMap = new LinkedMultiValueMap<>();
        requestBodyMap.add(REDIRECT_URI_LABEL, spotifyConfig.getSpotifyRedirectUri());
        requestBodyMap.add(GRANT_TYPE_LABEL, AUTHORIZATION_CODE_LABEL);
        requestBodyMap.add(SPOTIFY_RESPONSE_TYPE_CODE, authCode);

        return requestAccessToken(requestBodyMap);
    }

    private SpotifyToken requestAccessToken(MultiValueMap<String, String> requestBodyMap) throws SpotifyAPIException {
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

        SpotifyToken spotifyToken = new SpotifyToken();

        if (response.getStatusCode().is2xxSuccessful()) {
            Map<String, Object> responseBody = response.getBody();

            if (responseBody != null) {
                String refreshToken = (String) responseBody.get(REFRESH_TOKEN_LABEL);
                spotifyToken.setRefreshToken((refreshToken == null ? "" : refreshToken));
                spotifyToken.setAccessToken((String) responseBody.get(ACCESS_TOKEN_LABEL));
                spotifyToken.setTokenExpiry(
                        Instant.now().plusSeconds( (int) responseBody.get(EXPIRES_IN_LABEL))
                );
            }
        } else {
            throw new SpotifyAPIException("Spotify token could not be retrieved from the Spotify API");
        }
        return spotifyToken;
    }
}
