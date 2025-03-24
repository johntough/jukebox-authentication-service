package com.tough.jukebox.authentication.service;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tough.jukebox.authentication.config.VaultConfig;
import com.tough.jukebox.authentication.exceptions.VaultFailureException;
import com.tough.jukebox.authentication.model.VaultResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.*;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class VaultServiceTest {

    @Mock
    private RestTemplate restTemplate;

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private VaultConfig vaultConfig;

    @InjectMocks
    private VaultService vaultService;

    @Test
    void testIsHealthyReturnsTrueWhenHealthy() {

        when(vaultConfig.getVaultBaseUrl()).thenReturn("http://test-vault-base-url");
        when(vaultConfig.getVaultSystemHealthPath()).thenReturn("/test-vault-system-health-path/");

        when(restTemplate.exchange(
                "http://test-vault-base-url/test-vault-system-health-path/",
                HttpMethod.GET,
                null,
                String.class)
        ).thenReturn(ResponseEntity.ok("body"));

        boolean result = vaultService.isHealthy();

        assertTrue(result, "Expected Vault to be reported as healthy when HTTP status = (200 OK)");
    }

    @Test
    void testIsHealthyReturnsFalseWhenUnhealthy() {

        when(vaultConfig.getVaultBaseUrl()).thenReturn("http://test-vault-base-url");
        when(vaultConfig.getVaultSystemHealthPath()).thenReturn("/test-vault-system-health-path/");

        when(restTemplate.exchange(
                "http://test-vault-base-url/test-vault-system-health-path/",
                HttpMethod.GET,
                null,
                String.class)
        ).thenReturn(ResponseEntity.badRequest().body("body"));

        boolean result = vaultService.isHealthy();

        assertFalse(result, "Expected Vault to be reported as unhealthy when HTTP status = (400 BAD REQUEST)");
    }

    @Test
    void testIsHealthyReturnsFalseWhenHttpClientErrorException404NotFoundThrown() {

        when(vaultConfig.getVaultBaseUrl()).thenReturn("http://test-vault-base-url");
        when(vaultConfig.getVaultSystemHealthPath()).thenReturn("/test-vault-system-health-path/");

        when(restTemplate.exchange(
                "http://test-vault-base-url/test-vault-system-health-path/",
                HttpMethod.GET,
                null,
                String.class)
        ).thenThrow(new HttpClientErrorException(HttpStatus.NOT_FOUND, "Not Found"));

        boolean result = vaultService.isHealthy();
        assertFalse(result, "Expected Vault to be reported as unhealthy when exception is thrown (RuntimeException)");
    }

    @Test
    void testIsHealthyReturnsFalseWhenStatusCode301MovedPermanentlyReturned() {

        when(vaultConfig.getVaultBaseUrl()).thenReturn("http://test-vault-base-url");
        when(vaultConfig.getVaultSystemHealthPath()).thenReturn("/test-vault-system-health-path/");

        when(restTemplate.exchange(
                "http://test-vault-base-url/test-vault-system-health-path/",
                HttpMethod.GET,
                null,
                String.class)
        ).thenReturn(new ResponseEntity<>(HttpStatus.MOVED_PERMANENTLY));

        boolean result = vaultService.isHealthy();

        assertFalse(result, "Expected Vault to be reported as unhealthy when 301 MOVED_PERMANENTLY is returned  ");
    }

    @Test
    void testCreateSecretSuccess() throws VaultFailureException {

        when(vaultConfig.getXVaultTokenHeader()).thenReturn("test-vault-token-header");
        when(vaultConfig.getVaultToken()).thenReturn("test-vault-token");
        when(vaultConfig.getVaultBaseUrl()).thenReturn("http://test-vault-base-url");
        when(vaultConfig.getVaultKvV2Path()).thenReturn("/test-vault-kv-path/");

        when(restTemplate.exchange(
                eq("http://test-vault-base-url/test-vault-kv-path/test-key"),
                eq(HttpMethod.POST),
                any(HttpEntity.class),
                eq(String.class)
        )).thenReturn(ResponseEntity.ok("body"));

        vaultService.createSecret("test-key", new HashMap<>());

        verify(restTemplate, times(1)).exchange(
                eq("http://test-vault-base-url/test-vault-kv-path/test-key"),
                eq(HttpMethod.POST),
                any(HttpEntity.class),
                eq(String.class)
        );
    }

    @Test
    void testCreateSecretVaultFailureExceptionHandling400BadRequest() {

        when(vaultConfig.getXVaultTokenHeader()).thenReturn("test-vault-token-header");
        when(vaultConfig.getVaultToken()).thenReturn("test-vault-token");
        when(vaultConfig.getVaultBaseUrl()).thenReturn("http://test-vault-base-url");
        when(vaultConfig.getVaultKvV2Path()).thenReturn("/test-vault-kv-path/");

        when(restTemplate.exchange(
                eq("http://test-vault-base-url/test-vault-kv-path/test-key"),
                eq(HttpMethod.POST),
                any(HttpEntity.class),
                eq(String.class)
        )).thenReturn(ResponseEntity.badRequest().body("body"));


        VaultFailureException thrown = assertThrows(VaultFailureException.class, () -> {
            vaultService.createSecret("test-key", new HashMap<>());
        });

        assertEquals("Failed to store secret. HTTP response code: 400 BAD_REQUEST", thrown.getMessage());
    }

    @Test
    void testCreateSecretHttpClientErrorExceptionHandling404NotFound() {

        when(vaultConfig.getXVaultTokenHeader()).thenReturn("test-vault-token-header");
        when(vaultConfig.getVaultToken()).thenReturn("test-vault-token");
        when(vaultConfig.getVaultBaseUrl()).thenReturn("http://test-vault-base-url");
        when(vaultConfig.getVaultKvV2Path()).thenReturn("/test-vault-kv-path/");

        when(restTemplate.exchange(
                eq("http://test-vault-base-url/test-vault-kv-path/test-key"),
                eq(HttpMethod.POST),
                any(HttpEntity.class),
                eq(String.class)
        )).thenThrow(new HttpClientErrorException(HttpStatus.NOT_FOUND, "Not Found"));

        Map<String, String> testData = new HashMap<>();


        VaultFailureException thrown = assertThrows(VaultFailureException.class, () -> {
            vaultService.createSecret("test-key", testData);
        });

        assertEquals("Failed to store secret. HTTP response code: 404 NOT_FOUND", thrown.getMessage());
    }

    @Test
    void testReadSecretSuccess() throws VaultFailureException, JsonProcessingException {

        when(vaultConfig.getXVaultTokenHeader()).thenReturn("test-vault-token-header");
        when(vaultConfig.getVaultToken()).thenReturn("test-vault-token");
        when(vaultConfig.getVaultBaseUrl()).thenReturn("http://test-vault-base-url");
        when(vaultConfig.getVaultKvV2Path()).thenReturn("/test-vault-kv-path/");

        when(restTemplate.exchange(
                eq("http://test-vault-base-url/test-vault-kv-path/test-key"),
                eq(HttpMethod.GET),
                any(HttpEntity.class),
                eq(String.class)
        )).thenReturn(ResponseEntity.ok("{\"data\":\"{\"data\":{\"access_token\":\"test-token\", \"refresh_token\": \"test-refresh-token\"}}}"));

        VaultResponse vaultResponse = new VaultResponse();
        VaultResponse.Data data = new VaultResponse.Data();
        VaultResponse.Data.TokenData tokenData = new VaultResponse.Data.TokenData();
        tokenData.setAccess_token("test-token");
        tokenData.setRefresh_token("test-refresh-token");
        data.setData(tokenData);
        vaultResponse.setData(data);

        when(objectMapper.readValue(
                "{\"data\":\"{\"data\":{\"access_token\":\"test-token\", \"refresh_token\": \"test-refresh-token\"}}}",
                VaultResponse.class
        )).thenReturn(vaultResponse);

        VaultResponse returnedVaultResponse = vaultService.readSecret("test-key");

        assertEquals(vaultResponse, returnedVaultResponse);
    }

    @Test
    void testReadSecretVaultFailureExceptionHandling400BadRequest() {

        when(vaultConfig.getXVaultTokenHeader()).thenReturn("test-vault-token-header");
        when(vaultConfig.getVaultToken()).thenReturn("test-vault-token");
        when(vaultConfig.getVaultBaseUrl()).thenReturn("http://test-vault-base-url");
        when(vaultConfig.getVaultKvV2Path()).thenReturn("/test-vault-kv-path/");

        when(restTemplate.exchange(
                eq("http://test-vault-base-url/test-vault-kv-path/test-key"),
                eq(HttpMethod.GET),
                any(HttpEntity.class),
                eq(String.class)
        )).thenReturn(ResponseEntity.badRequest().body("body"));

        VaultFailureException thrown = assertThrows(VaultFailureException.class, () -> {
            vaultService.readSecret("test-key");
        });

        assertEquals("Failed to read secret. HTTP response code: 400 BAD_REQUEST", thrown.getMessage());
    }

    @Test
    void testReadSecretHttpClientErrorExceptionHandling404NotFound() {

        when(vaultConfig.getXVaultTokenHeader()).thenReturn("test-vault-token-header");
        when(vaultConfig.getVaultToken()).thenReturn("test-vault-token");
        when(vaultConfig.getVaultBaseUrl()).thenReturn("http://test-vault-base-url");
        when(vaultConfig.getVaultKvV2Path()).thenReturn("/test-vault-kv-path/");

        when(restTemplate.exchange(
                eq("http://test-vault-base-url/test-vault-kv-path/test-key"),
                eq(HttpMethod.GET),
                any(HttpEntity.class),
                eq(String.class)
        )).thenThrow(new HttpClientErrorException(HttpStatus.NOT_FOUND, "Not Found"));

        VaultFailureException thrown = assertThrows(VaultFailureException.class, () -> {
            vaultService.readSecret("test-key");
        });

        assertEquals("Failed to read secret. HTTP response code: 404 NOT_FOUND", thrown.getMessage());
    }

    @Test
    void testReadSecretJsonProcessingExceptionHandling() throws JsonProcessingException {

        when(vaultConfig.getXVaultTokenHeader()).thenReturn("test-vault-token-header");
        when(vaultConfig.getVaultToken()).thenReturn("test-vault-token");
        when(vaultConfig.getVaultBaseUrl()).thenReturn("http://test-vault-base-url");
        when(vaultConfig.getVaultKvV2Path()).thenReturn("/test-vault-kv-path/");

        when(restTemplate.exchange(
                eq("http://test-vault-base-url/test-vault-kv-path/test-key"),
                eq(HttpMethod.GET),
                any(HttpEntity.class),
                eq(String.class)
        )).thenReturn(ResponseEntity.ok("body"));

        when(objectMapper.readValue(
                "body",
                VaultResponse.class
        )).thenThrow(new JsonParseException("invalid-json"));

        VaultFailureException thrown = assertThrows(VaultFailureException.class, () -> {
            vaultService.readSecret("test-key");
        });

        assertEquals("Failed to read secret. Error parsing Json: invalid-json", thrown.getMessage());
    }
}