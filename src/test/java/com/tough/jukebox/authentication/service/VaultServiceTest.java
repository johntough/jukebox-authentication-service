package com.tough.jukebox.authentication.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
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

import static com.tough.jukebox.authentication.service.VaultService.getVaultSystemHealthPath;
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
                eq(vaultService.getVaultUrl() + getVaultSystemHealthPath()),
                eq(HttpMethod.GET),
                eq(null),
                eq(String.class))
        ).thenReturn(response);

        boolean result = vaultService.isHealthy();

        assertFalse(result, "Expected Vault to be reported as unhealthy when HTTP status = (501 NOT IMPLEMENTED)");
    }

    @Test
    void testIsHealthyRuntimeExceptionHandling() {

        when(restTemplate.exchange(
                eq(vaultService.getVaultUrl() + getVaultSystemHealthPath()),
                eq(HttpMethod.GET),
                eq(null),
                eq(String.class))
        ).thenThrow(new RuntimeException("Request failed"));

        boolean result = vaultService.isHealthy();

        assertFalse(result, "Expected Vault to be reported as unhealthy when exception is thrown (RuntimeException)");
    }

    @Test
    void testCreateSecretSuccess() throws VaultFailureException {

        ResponseEntity<String> response = mock(ResponseEntity.class);
        when(response.getStatusCode()).thenReturn(HttpStatus.OK);
        final String testKey = "test-key";

        when(restTemplate.exchange(
                eq(vaultService.getVaultUrl() + VaultService.getVaultKvV2Path() + testKey),
                eq(HttpMethod.POST),
                any(HttpEntity.class),
                eq(String.class)
        )).thenReturn(response);

        Map<String, String> testData = new HashMap<>();

        vaultService.createSecret(testKey, testData);

        verify(restTemplate, times(1)).exchange(
                eq(vaultService.getVaultUrl() + VaultService.getVaultKvV2Path() + testKey),
                eq(HttpMethod.POST),
                any(HttpEntity.class),
                eq(String.class)
        );
    }

    @Test
    void testCreateSecretVaultFailureExceptionHandling() {

        ResponseEntity<String> response = mock(ResponseEntity.class);
        when(response.getStatusCode()).thenReturn(HttpStatus.BAD_REQUEST);

        final String testKey = "test-key";

        when(restTemplate.exchange(
                eq(vaultService.getVaultUrl() + VaultService.getVaultKvV2Path() + testKey),
                eq(HttpMethod.POST),
                any(HttpEntity.class),
                eq(String.class)
        )).thenReturn(response);

        Map<String, String> testData = new HashMap<>();


        VaultFailureException thrown = assertThrows(VaultFailureException.class, () -> {
            vaultService.createSecret(testKey, testData);
        });

        assertEquals(HttpStatus.BAD_REQUEST, thrown.getStatusCode());
        assertEquals("Failed to store secret", thrown.getMessage());
    }

    @Test
    void testReadSecretSuccess() throws VaultFailureException, JsonProcessingException {

        ResponseEntity<String> response = mock(ResponseEntity.class);
        when(response.getStatusCode()).thenReturn(HttpStatus.OK);
        when(response.getBody()).thenReturn("body");

        VaultResponse vaultResponse = new VaultResponse();
        final String testKey = "test-key";

        when(restTemplate.exchange(
                eq(vaultService.getVaultUrl() + VaultService.getVaultKvV2Path() + testKey),
                eq(HttpMethod.GET),
                any(HttpEntity.class),
                eq(String.class)
        )).thenReturn(response);

        when(objectMapper.readValue(
                any(String.class),
                eq(VaultResponse.class)
        )).thenReturn(vaultResponse);

        VaultResponse returnedVaultResponse = vaultService.readSecret(testKey);

        assertEquals(vaultResponse, returnedVaultResponse);
    }

    @Test
    void testReadSecretVaultFailureExceptionHandling() throws VaultFailureException, JsonProcessingException {

        ResponseEntity<String> response = mock(ResponseEntity.class);
        when(response.getStatusCode()).thenReturn(HttpStatus.BAD_REQUEST);

        final String testKey = "test-key";

        when(restTemplate.exchange(
                eq(vaultService.getVaultUrl() + VaultService.getVaultKvV2Path() + testKey),
                eq(HttpMethod.GET),
                any(HttpEntity.class),
                eq(String.class)
        )).thenReturn(response);

        VaultFailureException thrown = assertThrows(VaultFailureException.class, () -> {
            vaultService.readSecret(testKey);
        });

        assertEquals(HttpStatus.BAD_REQUEST, thrown.getStatusCode());
        assertEquals("Failed to read secret", thrown.getMessage());
    }

    @Test
    void testReadSecretHttpClientErrorExceptionHandling() throws VaultFailureException, JsonProcessingException {

        VaultResponse vaultResponse = new VaultResponse();

        final String testKey = "test-key";

        when(restTemplate.exchange(
                eq(vaultService.getVaultUrl() + VaultService.getVaultKvV2Path() + testKey),
                eq(HttpMethod.GET),
                any(HttpEntity.class),
                eq(String.class)
        )).thenThrow(new HttpClientErrorException(HttpStatus.NOT_FOUND, "Not Found"));

        VaultFailureException thrown = assertThrows(VaultFailureException.class, () -> {
            vaultService.readSecret(testKey);
        });

        assertEquals(HttpStatus.NOT_FOUND, thrown.getStatusCode());
    }
}