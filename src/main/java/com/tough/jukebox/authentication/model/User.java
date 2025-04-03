package com.tough.jukebox.authentication.model;

import jakarta.persistence.*;

@Entity
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne(cascade = CascadeType.ALL, fetch = FetchType.EAGER)
    @JoinColumn(name = "spotify_token_id")
    private SpotifyToken spotifyToken;

    @Column(name = "spotify_user_id", nullable = false, unique = true)
    private String spotifyUserId;

    @Column(name = "email_address", nullable = false, unique = true)
    private String emailAddress;

    @Column(name = "displayName", nullable = false, unique = true)
    private String displayName;

    public Long getId() { return id; }

    public String getEmailAddress() { return emailAddress; }

    public void setEmailAddress(String emailAddress) { this.emailAddress = emailAddress; }

    public String getDisplayName() { return displayName; }

    public void setDisplayName(String displayName) { this.displayName = displayName; }

    public String getSpotifyUserId() { return spotifyUserId; }

    public void setSpotifyUserId(String spotifyUserId) { this.spotifyUserId = spotifyUserId; }

    public SpotifyToken getSpotifyToken() { return spotifyToken; }

    public void setSpotifyToken(SpotifyToken spotifyToken) { this.spotifyToken = spotifyToken; }
}