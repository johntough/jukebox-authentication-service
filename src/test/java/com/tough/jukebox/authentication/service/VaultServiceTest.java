package com.tough.jukebox.authentication.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

public class VaultServiceTest {

    @Mock
    private RestTemplate restTemplate;

    @InjectMocks
    private VaultService vaultService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    public void testIsHealthy_healthy() {

        ResponseEntity<String> response = new ResponseEntity<>(HttpStatus.OK);

        when(restTemplate.exchange(
                any(String.class),
                eq(HttpMethod.GET),
                eq(null),
                eq(String.class))
        ).thenReturn(response);

        boolean result = vaultService.isHealthy();

        assertTrue(result, "Vault should be healthy when response is OK");
    }

    @Test
    public void testIsHealthy_unhealthy() {

        ResponseEntity<String> response = new ResponseEntity<>(HttpStatus.NOT_IMPLEMENTED);

        when(restTemplate.exchange(
                any(String.class),
                eq(HttpMethod.GET),
                eq(null),
                eq(String.class))
        ).thenReturn(response);

        boolean result = vaultService.isHealthy();

        assertFalse(result, "Vault should NOT be healthy when response is Not Implemented");
    }

    @Test
    public void testIsHealthy_exception_handling() {

        ResponseEntity<String> response = new ResponseEntity<>(HttpStatus.NOT_IMPLEMENTED);

        when(restTemplate.exchange(
                any(String.class),
                eq(HttpMethod.GET),
                eq(null),
                eq(String.class))
        ).thenThrow(new RuntimeException("Request failed"));

        boolean result = vaultService.isHealthy();

        assertFalse(result, "Vault should NOT be healthy when exception is thrown");
    }
}