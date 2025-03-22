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

        ResponseEntity<String> response = mock(ResponseEntity.class);
        when(response.getStatusCode()).thenReturn(HttpStatus.OK);

        when(restTemplate.exchange(
                any(String.class),
                eq(HttpMethod.GET),
                eq(null),
                eq(String.class))
        ).thenReturn(response);

        boolean result = vaultService.isHealthy();

        assertTrue(result, "Expected Vault to be reported as healthy when HTTP status = (200 OK)");
    }

    @Test
    void testIsHealthyReturnsFalseWhenUnhealthy() {

        ResponseEntity<String> response = mock(ResponseEntity.class);
        when(response.getStatusCode()).thenReturn(HttpStatus.NOT_IMPLEMENTED);

        when(restTemplate.exchange(
                eq(vaultConfig.getVaultBaseUrl() + vaultConfig.getVaultSystemHealthPath()),
                eq(HttpMethod.GET),
                eq(null),
                eq(String.class))
        ).thenReturn(response);

        boolean result = vaultService.isHealthy();

        assertFalse(result, "Expected Vault to be reported as unhealthy when HTTP status = (501 NOT IMPLEMENTED)");
    }

    @Test
    void testIsHealthyReturnsFalseWhenHttpClientErrorException404NotFoundThrown() {

        when(restTemplate.exchange(
                eq(vaultConfig.getVaultBaseUrl() + vaultConfig.getVaultSystemHealthPath()),
                eq(HttpMethod.GET),
                eq(null),
                eq(String.class))
        ).thenThrow(new HttpClientErrorException(HttpStatus.NOT_FOUND, "Not Found"));

        boolean result = vaultService.isHealthy();

        assertFalse(result, "Expected Vault to be reported as unhealthy when exception is thrown (RuntimeException)");
    }

    @Test
    void testIsHealthyReturnsFalseWhenStatusCode301MovedPermanentlyReturned() {

        ResponseEntity<String> response = mock(ResponseEntity.class);
        when(response.getStatusCode()).thenReturn(HttpStatus.MOVED_PERMANENTLY);

        when(restTemplate.exchange(
                eq(vaultConfig.getVaultBaseUrl() + vaultConfig.getVaultSystemHealthPath()),
                eq(HttpMethod.GET),
                eq(null),
                eq(String.class))
        ).thenReturn(response);

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

        ResponseEntity<String> response = new ResponseEntity<>(
                "{\"data\":\"{\"data\":{\"access_token\":\"test-token\", \"refresh_token\": \"test-refresh-token\"}}}",
                HttpStatus.OK
        );

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
                eq("{\"data\":\"{\"data\":{\"access_token\":\"test-token\", \"refresh_token\": \"test-refresh-token\"}}}"),
                eq(VaultResponse.class)
        )).thenReturn(vaultResponse);

        VaultResponse returnedVaultResponse = vaultService.readSecret("test-key");

        assertEquals(vaultResponse, returnedVaultResponse);
    }

    @Test
    void testReadSecretVaultFailureExceptionHandling400BadRequest() throws VaultFailureException, JsonProcessingException {

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
    void testReadSecretHttpClientErrorExceptionHandling404NotFound() throws VaultFailureException, JsonProcessingException {

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
    void testReadSecretJsonProcessingExceptionHandling() throws VaultFailureException, JsonProcessingException {

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
                eq("body"),
                eq(VaultResponse.class)
        )).thenThrow(new JsonParseException("invalid-json"));

        VaultFailureException thrown = assertThrows(VaultFailureException.class, () -> {
            vaultService.readSecret("test-key");
        });

        assertEquals("Failed to read secret. Error parsing Json: invalid-json", thrown.getMessage());
    }
}