package com.tough.jukebox.authentication.model;

import jakarta.persistence.*;

import java.time.Instant;

@Entity
public class SpotifyToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne(mappedBy = "spotifyToken")
    private User user;

    @Column(name = "access_token", nullable = false, unique = true)
    private String accessToken;

    @Column(name = "refresh_token", nullable = false, unique = true)
    private String refreshToken;

    @Column(name = "token_expiry", nullable = false)
    private Instant tokenExpiry;

    public String getRefreshToken() { return refreshToken; }

    public void setRefreshToken(String refreshToken) { this.refreshToken = refreshToken; }

    public String getAccessToken() { return accessToken; }

    public void setAccessToken(String accessToken) { this.accessToken = accessToken; }

    public User getUser() { return user; }

    public void setUser(User user) { this.user = user; }

    public Instant getTokenExpiry() { return tokenExpiry; }

    public void setTokenExpiry(Instant tokenExpiry) { this.tokenExpiry = tokenExpiry; }
}