package com.tough.jukebox.authentication.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Configuration
public class VaultConfig {

    @Value(value = "${X_VAULT_TOKEN_HEADER}")
    private String xVaultTokenHeader;

    @Value(value = "${VAULT_KV_V2_PATH}")
    private String vaultKvV2Path;

    @Value(value = "${VAULT_SYSTEM_HEALTH_PATH}")
    private String vaultSystemHealthPath;

    @Value(value = "${VAULT_ADDRESS}")
    private String vaultBaseUrl;

    @Value(value = "${VAULT_TOKEN_ID}")
    private String vaultToken;

    public String getXVaultTokenHeader() { return xVaultTokenHeader; }

    public String getVaultKvV2Path() { return vaultKvV2Path; }

    public String getVaultSystemHealthPath() { return vaultSystemHealthPath; }

    public String getVaultBaseUrl() { return vaultBaseUrl; }

    public String getVaultToken() { return vaultToken; }
}