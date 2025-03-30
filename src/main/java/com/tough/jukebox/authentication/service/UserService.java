package com.tough.jukebox.authentication.service;

import com.tough.jukebox.authentication.model.SpotifyToken;
import com.tough.jukebox.authentication.model.User;
import com.tough.jukebox.authentication.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Service
public class UserService {

    private static final Logger LOGGER = LoggerFactory.getLogger(UserService.class);

    private final UserRepository userRepository;

    @Autowired
    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public Optional<User> getUserBySpotifyUserId(String spotifyUserId) {
        return userRepository.findBySpotifyUserId(spotifyUserId);
    }

    public List<User> getUsersWithExpiringTokens(Instant currentTime, Instant expiryTime) {
        return userRepository.findUsersWithSpotifyTokenExpiringSoon(currentTime, expiryTime);
    }

    public boolean clearUserTokens(String spotifyUserId) {
        return userRepository.findBySpotifyUserId(spotifyUserId)
                .map(returnedUser -> {
                    returnedUser.setSpotifyToken(null);
                    userRepository.save(returnedUser);
                    LOGGER.info("User's Spotify tokens cleared: {}", returnedUser.getDisplayName());
                    return true;
                })
                .orElse(false);
    }

    public void updateUserTokens(User user, SpotifyToken newSpotifyToken) {
        SpotifyToken spotifyToken = Optional.ofNullable(user.getSpotifyToken())
                .orElse(new SpotifyToken());

        spotifyToken.setAccessToken(newSpotifyToken.getAccessToken());
        spotifyToken.setTokenExpiry(newSpotifyToken.getTokenExpiry());

        if (!newSpotifyToken.getRefreshToken().isEmpty()) {
            spotifyToken.setRefreshToken(newSpotifyToken.getRefreshToken());
        }

        user.setSpotifyToken(spotifyToken);
        userRepository.save(user);
        LOGGER.info("Spotify access token updated for user: {}. Token valid until: {}", user.getSpotifyUserId(), newSpotifyToken.getTokenExpiry());
    }
}