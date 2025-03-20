package com.tough.jukebox.authentication.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tough.jukebox.authentication.exceptions.VaultFailureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import com.tough.jukebox.authentication.model.VaultResponse;
import java.util.HashMap;
import java.util.Map;

@Service
public class VaultService {

    private static final Logger logger = LoggerFactory.getLogger(VaultService.class);

    @Value(value = "${VAULT_ADDRESS}")
    private String vaultUrl;

    @Value(value = "${VAULT_TOKEN_ID}")
    private String vaultToken;

    private static final String X_VAULT_TOKEN_HEADER = "X-Vault-Token";
    private static final String VAULT_KV_V2_PATH = "/v1/secret/data/";
    private static final String VAULT_SYSTEM_HEALTH_PATH = "/v1/sys/health";

    private final ObjectMapper objectMapper;
    private final RestTemplate restTemplate;

    @Autowired
    public VaultService(RestTemplate restTemplate, ObjectMapper objectMapper) {
        this.restTemplate = restTemplate;
        this.objectMapper = objectMapper;
    }

    public boolean isHealthy() {

        boolean isHealthy = false;
        try {
            ResponseEntity<String> response = restTemplate.exchange(
                    getVaultUrl() + getVaultSystemHealthPath(),
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

    public void createSecret(String key, Map<String, String> secretData) throws VaultFailureException {

        HttpHeaders headers = new HttpHeaders();
        headers.set(getXVaultTokenHeader(), getVaultToken());
        headers.setContentType(MediaType.APPLICATION_JSON);

        Map<String, Object> payload = new HashMap<>();
        payload.put("data", secretData);

        HttpEntity<Map<String, Object>> request = new HttpEntity<>(payload, headers);

        ResponseEntity<String> response = restTemplate.exchange(
                getVaultUrl() + getVaultKvV2Path() + key,
                HttpMethod.POST,
                request,
                String.class
        );

        if (response.getStatusCode().is2xxSuccessful()) {
            logger.info("Secret stored successfully!");
        } else {
            throw new VaultFailureException("Failed to store secret", response.getStatusCode());
        }
    }

    public VaultResponse readSecret(String key) throws VaultFailureException {

        VaultResponse vaultResponse = null;

        HttpHeaders headers = new HttpHeaders();
        headers.set(getXVaultTokenHeader(), getVaultToken());
        headers.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<String> request = new HttpEntity<>(null, headers);

        try {
            ResponseEntity<String> response = restTemplate.exchange(
                    getVaultUrl() + getVaultKvV2Path() + key,
                    HttpMethod.GET,
                    request,
                    String.class
            );
            if (response.getStatusCode().is2xxSuccessful()) {
                logger.info("Secret retrieved successfully!");

                try {
                    vaultResponse = objectMapper.readValue(response.getBody(), VaultResponse.class);
                } catch (JsonProcessingException e) {
                    logger.error("Error parsing Json: {}", e.getMessage());
                    vaultResponse = new VaultResponse();
                }

            } else {
                throw new VaultFailureException("Failed to read secret", response.getStatusCode());
            }
        } catch (HttpClientErrorException e) {
            throw new VaultFailureException("Failed to read secret", e.getStatusCode());
        }

        return vaultResponse;
    }

    public String getVaultUrl() {
        return vaultUrl;
    }

    public String getVaultToken() {
        return vaultToken;
    }

    public static String getXVaultTokenHeader() {
        return X_VAULT_TOKEN_HEADER;
    }

    public static String getVaultKvV2Path() {
        return VAULT_KV_V2_PATH;
    }

    public static String getVaultSystemHealthPath() {
        return VAULT_SYSTEM_HEALTH_PATH;
    }
}