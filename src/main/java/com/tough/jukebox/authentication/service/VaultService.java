package com.tough.jukebox.authentication.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tough.jukebox.authentication.config.VaultConfig;
import com.tough.jukebox.authentication.exceptions.VaultFailureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
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

    private final ObjectMapper objectMapper;
    private final RestTemplate restTemplate;
    private final VaultConfig vaultConfig;

    @Autowired
    public VaultService(RestTemplate restTemplate, ObjectMapper objectMapper, VaultConfig vaultConfig) {
        this.restTemplate = restTemplate;
        this.objectMapper = objectMapper;
        this.vaultConfig = vaultConfig;
    }

    public boolean isHealthy() {

        try {
            ResponseEntity<String> response = restTemplate.exchange(
                    vaultConfig.getVaultBaseUrl() + vaultConfig.getVaultSystemHealthPath(),
                    HttpMethod.GET,
                    null,
                    String.class
            );

            if (response.getStatusCode() == HttpStatus.OK) {
                logger.info("Vault is healthy. Status code: {}", response.getStatusCode());
                return true;
            } else {
                logger.error("Vault is not healthy. Status code: {}", response.getStatusCode());
                return false;
            }
        } catch (HttpClientErrorException e) {
            logger.error("HttpClientErrorException when attempting to check Vault Health status: {}", e.getMessage());
            return false;
        }
    }

    public void createSecret(String key, Map<String, String> secretData) throws VaultFailureException {

        HttpHeaders headers = new HttpHeaders();
        headers.set(vaultConfig.getXVaultTokenHeader(), vaultConfig.getVaultToken());
        headers.setContentType(MediaType.APPLICATION_JSON);

        Map<String, Object> payload = new HashMap<>();
        payload.put("data", secretData);

        HttpEntity<Map<String, Object>> request = new HttpEntity<>(payload, headers);

        try {
            ResponseEntity<String> response = restTemplate.exchange(
                    vaultConfig.getVaultBaseUrl() + vaultConfig.getVaultKvV2Path() + key,
                    HttpMethod.POST,
                    request,
                    String.class
            );

            if (response.getStatusCode().is2xxSuccessful()) {
                logger.info("Secret stored successfully!");
            } else {
                throw new VaultFailureException("Failed to store secret. HTTP response code: " + response.getStatusCode());
            }
        } catch (HttpClientErrorException e) {
            throw new VaultFailureException("Failed to store secret. HTTP response code: " + e.getStatusCode());
        }
    }

    public VaultResponse readSecret(String key) throws VaultFailureException {

        VaultResponse vaultResponse = null;

        HttpHeaders headers = new HttpHeaders();
        headers.set(vaultConfig.getXVaultTokenHeader(), vaultConfig.getVaultToken());
        headers.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<String> request = new HttpEntity<>(null, headers);

        try {
            ResponseEntity<String> response = restTemplate.exchange(
                    vaultConfig.getVaultBaseUrl() + vaultConfig.getVaultKvV2Path() + key,
                    HttpMethod.GET,
                    request,
                    String.class
            );
            if (response.getStatusCode().is2xxSuccessful()) {
                logger.info("Secret retrieved successfully!");
                vaultResponse = objectMapper.readValue(response.getBody(), VaultResponse.class);
            } else {
                throw new VaultFailureException("Failed to read secret. HTTP response code: " + response.getStatusCode());
            }
        } catch (HttpClientErrorException e) {
            throw new VaultFailureException("Failed to read secret. HTTP response code: " + e.getStatusCode());
        } catch (JsonProcessingException e) {
            throw new VaultFailureException("Failed to read secret. Error parsing Json: " + e.getMessage());
        }

        return vaultResponse;
    }
}