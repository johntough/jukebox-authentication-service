package com.tough.jukebox.authentication.service;

import com.tough.jukebox.authentication.exceptions.VaultFailureException;
import com.tough.jukebox.authentication.model.VaultResponse;
import org.apache.hc.core5.net.URIBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.scheduling.annotation.Scheduled;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@Service
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    @Value(value = "${SPOTIFY_REDIRECT_URI}")
    private String spotifyRedirectUri;

    @Value(value = "${CLIENT_ID}")
    private String clientId;

    @Value(value = "${CLIENT_SECRET}")
    private String clientSecret;

    @Value(value = "${FRONT_END_REDIRECT}")
    private String frontendRedirectUri;

    private static final String ACCESS_TOKEN_NAME = "access_token";
    private static final String REFRESH_TOKEN_NAME = "refresh_token";
    private static final String SPOTIFY_TOKEN_URI = "https://accounts.spotify.com/api/token";
    private static final String SPOTIFY_AUTHORIZE_URI = "https://accounts.spotify.com/authorize/";

    private boolean tokenRefreshProcessEnabled = false;
    private int expiresIn = 0;

    private final VaultService vaultService;

    @Autowired
    public AuthService(VaultService vaultService) {
        this.vaultService = vaultService;
    }

    public String login(String scope) throws URISyntaxException {

        URIBuilder uriBuilder = new URIBuilder(SPOTIFY_AUTHORIZE_URI);
        uriBuilder.addParameter("response_type", "code");
        uriBuilder.addParameter("client_id", clientId);
        uriBuilder.addParameter("scope", scope);
        uriBuilder.addParameter("redirect_uri", spotifyRedirectUri);

        String uri = uriBuilder.build().toString();

        logger.info("Redirecting user to Spotify authorization page");

        return "{\"redirectUri\":\"" + uri + "\"}";
    }

    public ResponseEntity<Void> callback(String authCode) {

        MultiValueMap<String, String> requestBodyMap = new LinkedMultiValueMap<>();
        requestBodyMap.add("redirect_uri", spotifyRedirectUri);
        requestBodyMap.add("grant_type", "authorization_code");
        requestBodyMap.add("code", authCode);

        getAccessToken(requestBodyMap);

        return ResponseEntity.status(HttpStatus.FOUND)  // 302 Redirect
                .location(URI.create(frontendRedirectUri))
                .build();
    }

    public String getToken() {

        VaultResponse response;

        try {
            response = vaultService.readSecret(ACCESS_TOKEN_NAME);
        } catch (VaultFailureException exception) {
            response = new VaultResponse();

            logger.error("Error reading from Vault. Status Code: {}",
                    exception.getStatusCode()
            );
        }

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
        requestBodyMap.add("grant_type", REFRESH_TOKEN_NAME);

        try {
            String existingRefreshToken = vaultService.readSecret(ACCESS_TOKEN_NAME).getData().getData().getRefresh_token();
            requestBodyMap.add(REFRESH_TOKEN_NAME, existingRefreshToken);

            getAccessToken(requestBodyMap);
        } catch (VaultFailureException exception) {
            logger.error("Error reading from Vault: {}, Status Code: {}",
                    exception.getMessage(),
                    exception.getStatusCode()
            );
        }

    }

    private void getAccessToken(MultiValueMap<String, String> requestBodyMap) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setBasicAuth(Base64.getEncoder().encodeToString((clientId + ":" + clientSecret).getBytes()));

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(requestBodyMap, headers);

        RestTemplate restTemplate = new RestTemplate();

        try {
            Map<String, Object> response = restTemplate.postForObject(SPOTIFY_TOKEN_URI, request, Map.class);

            if (response != null) {

                String existingRefreshToken = vaultService.readSecret(ACCESS_TOKEN_NAME).getData().getData().getRefresh_token();

                String localAccessToken = (String) response.get(ACCESS_TOKEN_NAME);
                String localRefreshToken = (Objects.isNull(response.get(REFRESH_TOKEN_NAME))) ? existingRefreshToken : (String) response.get(REFRESH_TOKEN_NAME);
                expiresIn = (int) response.get("expires_in");
                tokenRefreshProcessEnabled = true;

                // send secrets to Vault
                Map<String, String> secretData = new HashMap<>();
                secretData.put(ACCESS_TOKEN_NAME, localAccessToken);
                secretData.put(REFRESH_TOKEN_NAME, localRefreshToken);
                vaultService.createSecret(ACCESS_TOKEN_NAME, secretData);

                logger.info("Access token successfully extracted");
                logger.info("Access token valid for {} minutes", expiresIn/60);
            }
        } catch(HttpClientErrorException exception) {
            logger.error("HttpClientErrorException: message: {} ",
                    exception.getMessage()
            );
        } catch (VaultFailureException exception) {
            logger.error("Error when interacting with Vault: {}, Status Code: {}",
                    exception.getMessage(),
                    exception.getStatusCode()
            );
        }
    }
}