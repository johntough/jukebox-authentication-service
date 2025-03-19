package com.tough.jukebox.authentication.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import com.tough.jukebox.authentication.model.VaultResponse;
import java.util.HashMap;
import java.util.Map;

@Service
public class VaultService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    @Value(value = "${VAULT_ADDRESS}")
    private String vaultUrl;

    @Value(value = "${VAULT_TOKEN_ID}")
    private String vaultToken;

    private static final String ACCESS_TOKEN_NAME = "access_token";
    private static final String X_VAULT_TOKEN_HEADER = "X-Vault-Token";
    private static final String VAULT_KV_V2_PATH = "/v1/secret/data/";
    private static final String VAULT_SYSTEM_HEALTH_PATH = "/v1/sys/health";

    @Autowired
    private ObjectMapper objectMapper;

    public boolean isHealthy() {

        boolean isHealthy = false;
        try {
            RestTemplate restTemplate = new RestTemplate();
            ResponseEntity<String> response = restTemplate.exchange(
                    vaultUrl + VAULT_SYSTEM_HEALTH_PATH,
                    HttpMethod.GET,
                    null,
                    String.class
            );

            if (response.getStatusCode() == HttpStatus.OK) {
                isHealthy = true;
                logger.info("Vault is healthy. Status code: {}", response.getStatusCode());
            } else {
                logger.error("Vault is not healthy. Status code: {}", response.getStatusCode());
            }

        } catch (Exception e) {
            logger.error("Request failed: {}", e.toString());
            return isHealthy;
        }

        return isHealthy;
    }

    public void createSecret(String key, Map<String, String> secretData) {

        try {
            HttpHeaders headers = new HttpHeaders();
            headers.set(X_VAULT_TOKEN_HEADER, vaultToken);
            headers.setContentType(MediaType.APPLICATION_JSON);

            Map<String, Object> payload = new HashMap<>();
            payload.put("data", secretData);

            HttpEntity<Map<String, Object>> request = new HttpEntity<>(payload, headers);

            RestTemplate restTemplate = new RestTemplate();

            ResponseEntity<String> response = restTemplate.exchange(
                    vaultUrl + VAULT_KV_V2_PATH + key,
                    HttpMethod.POST,
                    request,
                    String.class
            );

            if (response.getStatusCode().is2xxSuccessful()) {
                logger.info("Secret stored successfully!");
            } else {
                logger.error("Failed to store secret. Status code: {}", response.getStatusCode());
            }
        } catch (Exception e) {
            logger.error("Request failed: {}", e.toString());
        }
    }

    public VaultResponse readSecret() {

        VaultResponse vaultResponse = null;

        try {
            HttpHeaders headers = new HttpHeaders();
            headers.set(X_VAULT_TOKEN_HEADER, vaultToken);
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<String> request = new HttpEntity<>(null, headers);

            RestTemplate restTemplate = new RestTemplate();

            ResponseEntity<String> response = restTemplate.exchange(
                    vaultUrl + VAULT_KV_V2_PATH + ACCESS_TOKEN_NAME,
                    HttpMethod.GET,
                    request,
                    String.class
            );

            if (response.getStatusCode().is2xxSuccessful()) {
                logger.info("Secret retrieved successfully!");

                vaultResponse = objectMapper.readValue(response.getBody(), VaultResponse.class);
                
            } else {
                logger.error("Error returned from Vault: {}. Status code: {}",
                        response.getBody(),
                        response.getStatusCode()
                );
            }
        } catch (Exception e) {
            vaultResponse = new VaultResponse();
            logger.error("Request failed: {}", e.toString());
        }

        return vaultResponse;
    }
}