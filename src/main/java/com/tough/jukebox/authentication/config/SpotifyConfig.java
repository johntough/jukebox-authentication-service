package com.tough.jukebox.authentication.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SpotifyConfig {

    @Value(value = "${SPOTIFY_REDIRECT_URI}")
    private String spotifyRedirectUri;

    @Value(value = "${SPOTIFY_APP_CLIENT_ID}")
    private String spotifyAppClientId;

    @Value(value = "${SPOTIFY_APP_CLIENT_SECRET}")
    private String spotifyAppClientSecret;

    @Value(value = "${SPOTIFY_TOKEN_URI}")
    private String spotifyTokenUri;

    public String getSpotifyRedirectUri() {
        return spotifyRedirectUri;
    }

    public String getSpotifyAppClientId() {
        return spotifyAppClientId;
    }

    public String getSpotifyAppClientSecret() {
        return spotifyAppClientSecret;
    }

    public String getSpotifyTokenUri() { return spotifyTokenUri; }
}
