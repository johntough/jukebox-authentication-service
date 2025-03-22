package com.tough.jukebox.authentication.service;

import com.tough.jukebox.authentication.config.SpotifyConfig;
import com.tough.jukebox.authentication.config.WebConfig;
import com.tough.jukebox.authentication.exceptions.VaultFailureException;
import com.tough.jukebox.authentication.model.VaultResponse;
import org.apache.hc.core5.net.URIBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.scheduling.annotation.Scheduled;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Service
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    public static final String ACCESS_TOKEN_NAME = "access_token";
    public static final String REFRESH_TOKEN_NAME = "refresh_token";
    public static final String AUTHORIZATION_CODE_NAME = "authorization_code";
    public static final String GRANT_TYPE_NAME = "grant_type";
    public static final String REDIRECT_URI_NAME = "redirect_uri";
    public static final String EXPIRES_IN_NAME = "expires_in";
    public static final String CLIENT_ID_NAME = "client_id";
    public static final String SCOPE_NAME = "scope";
    public static final String RESPONSE_TYPE_NAME = "response_type";
    public static final String SPOTIFY_RESPONSE_TYPE_CODE = "code";

    private boolean tokenRefreshProcessEnabled = false;
    private int expiresIn = 0;

    private final VaultService vaultService;
    private final RestTemplate restTemplate;
    private final SpotifyConfig spotifyConfig;
    private final WebConfig webConfig;

    @Autowired
    public AuthService(VaultService vaultService, RestTemplate restTemplate, SpotifyConfig serviceConfig, WebConfig webConfig) {
        this.vaultService = vaultService;
        this.restTemplate = restTemplate;
        this.spotifyConfig = serviceConfig;
        this.webConfig = webConfig;
    }

    public String returnSpotifyLoginRedirectUri(String scope) throws URISyntaxException {

        URIBuilder uriBuilder = new URIBuilder(spotifyConfig.getSpotifyAuthorizeUri());
        uriBuilder.addParameter(RESPONSE_TYPE_NAME, SPOTIFY_RESPONSE_TYPE_CODE);
        uriBuilder.addParameter(CLIENT_ID_NAME, spotifyConfig.getSpotifyAppClientId());
        uriBuilder.addParameter(SCOPE_NAME, scope);
        uriBuilder.addParameter(REDIRECT_URI_NAME, spotifyConfig.getSpotifyRedirectUri());

        String uri = uriBuilder.build().toString();

        logger.info("Redirecting user to Spotify authorization page");

        return "{\"redirectUri\":\"" + uri + "\"}";
    }

    public ResponseEntity<Void> spotifyAuthorizationCallback(String authCode) {

        MultiValueMap<String, String> requestBodyMap = new LinkedMultiValueMap<>();
        requestBodyMap.add(REDIRECT_URI_NAME, spotifyConfig.getSpotifyRedirectUri());
        requestBodyMap.add(GRANT_TYPE_NAME, AUTHORIZATION_CODE_NAME);
        requestBodyMap.add(SPOTIFY_RESPONSE_TYPE_CODE, authCode);

        requestAccessTokenFromSpotifyAndStoreInVault(requestBodyMap);

        return ResponseEntity.status(HttpStatus.FOUND)  // 302 Redirect
                .location(URI.create(webConfig.getFrontendRedirectUri()))
                .build();
    }

    public String returnAccessTokenJson() {
        VaultResponse response = fetchAccessTokenFromVault();
        String returnedToken = response.getData().getData().getAccess_token();

        return "{\"accessToken\":\"" + returnedToken + "\"}";
    }

    @Scheduled(fixedRate = 60000)  // Runs every minute
    private void checkTokenRefresh() {
        if (tokenRefreshProcessEnabled) {
            if (expiresIn <= 300) { // 5 minutes
                refreshAccessToken();
            } else {
                expiresIn = expiresIn - 60;
            }
        }
    }

    private void refreshAccessToken() {
        logger.info("Initiating token refresh process");

        MultiValueMap<String, String> requestBodyMap = new LinkedMultiValueMap<>();
        requestBodyMap.add(GRANT_TYPE_NAME, REFRESH_TOKEN_NAME);

        String existingRefreshToken = fetchAccessTokenFromVault().getData().getData().getRefresh_token();
        requestBodyMap.add(REFRESH_TOKEN_NAME, existingRefreshToken);

        requestAccessTokenFromSpotifyAndStoreInVault(requestBodyMap);
    }

    private VaultResponse fetchAccessTokenFromVault() {
        try {
            return vaultService.readSecret(ACCESS_TOKEN_NAME);
        } catch (VaultFailureException e) {
            logger.error("Error reading from Vault: {}", e.getMessage());
            return new VaultResponse();
        }
    }

    private void requestAccessTokenFromSpotifyAndStoreInVault(MultiValueMap<String, String> requestBodyMap) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setBasicAuth(Base64.getEncoder().encodeToString((spotifyConfig.getSpotifyAppClientId() + ":" + spotifyConfig.getSpotifyAppClientSecret()).getBytes()));

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(requestBodyMap, headers);

        Map<String, Object> response = restTemplate.postForObject(
                spotifyConfig.getSpotifyTokenUri(),
                request,
                Map.class
        );

        if (response != null) {
            storeTokenInVault(response);
        }
    }

    private void storeTokenInVault(Map<String, Object> response) {
        String accessToken = (String) response.get(ACCESS_TOKEN_NAME);
        String refreshToken = (String) response.getOrDefault(REFRESH_TOKEN_NAME, fetchAccessTokenFromVault());

        Map<String, String> secretData = new HashMap<>();
        secretData.put(ACCESS_TOKEN_NAME, accessToken);
        secretData.put(REFRESH_TOKEN_NAME, refreshToken);
        try {
            vaultService.createSecret(ACCESS_TOKEN_NAME, secretData);
            expiresIn = (int) response.get(EXPIRES_IN_NAME);
            tokenRefreshProcessEnabled = true;
            logger.info("Access token successfully extracted and saved to Vault, valid for {} minutes", expiresIn / 60);
        } catch (VaultFailureException e) {
            logger.error("Error when saving access token to Vault: {}", e.getMessage());
        }
    }
}