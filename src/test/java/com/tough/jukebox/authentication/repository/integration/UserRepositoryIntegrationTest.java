package com.tough.jukebox.authentication.repository.integration;

import com.tough.jukebox.authentication.model.SpotifyToken;
import com.tough.jukebox.authentication.model.User;
import com.tough.jukebox.authentication.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@DataJpaTest
@ActiveProfiles("test")
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class UserRepositoryIntegrationTest {

    @Autowired
    UserRepository userRepository;

    @Test
    void testSaveUser() {
        User user = new User();
        user.setSpotifyUserId("testSpotifyUserId");
        user.setEmailAddress("test@email.address");
        user.setDisplayName("testDisplayName");
        User savedUser = userRepository.save(user);

        assertNotNull(savedUser.getId());
        assertEquals("testSpotifyUserId", savedUser.getSpotifyUserId());
        assertEquals("test@email.address", savedUser.getEmailAddress());
        assertEquals("testDisplayName", savedUser.getDisplayName());
    }

    @Test
    void testSaveSpotifyToken() {
        User user = new User();
        user.setSpotifyUserId("testSpotifyUserId");
        user.setEmailAddress("test@email.address");
        user.setDisplayName("testDisplayName");

        SpotifyToken spotifyToken = new SpotifyToken();

        spotifyToken.setTokenExpiry(LocalDateTime.of(2025, 4, 4, 12, 30).toInstant(ZoneOffset.UTC));
        spotifyToken.setAccessToken("test-access-token");
        spotifyToken.setRefreshToken("test-refresh-token");
        user.setSpotifyToken(spotifyToken);

        User savedUser = userRepository.save(user);

        assertNotNull(savedUser.getSpotifyToken());
        assertEquals("test-access-token", savedUser.getSpotifyToken().getAccessToken());
        assertEquals("test-refresh-token", savedUser.getSpotifyToken().getRefreshToken());
        assertEquals(
                LocalDateTime.of(2025, 4, 4, 12, 30).toInstant(ZoneOffset.UTC),
                savedUser.getSpotifyToken().getTokenExpiry()
        );
    }

    @Test
    void testUpdateSpotifyToken() {
        User user = new User();
        user.setSpotifyUserId("testSpotifyUserId");
        user.setEmailAddress("test@email.address");
        user.setDisplayName("testDisplayName");

        SpotifyToken spotifyToken = new SpotifyToken();
        spotifyToken.setTokenExpiry(LocalDateTime.of(2025, 4, 4, 11, 30).toInstant(ZoneOffset.UTC));
        spotifyToken.setAccessToken("test-access-token-original");
        spotifyToken.setRefreshToken("test-refresh-token-original");
        user.setSpotifyToken(spotifyToken);

        User originalSavedUser = userRepository.save(user);

        assertNotNull(originalSavedUser.getSpotifyToken());
        assertEquals("test-access-token-original", originalSavedUser.getSpotifyToken().getAccessToken());
        assertEquals("test-refresh-token-original", originalSavedUser.getSpotifyToken().getRefreshToken());
        assertEquals(
                LocalDateTime.of(2025, 4, 4, 11, 30).toInstant(ZoneOffset.UTC),
                originalSavedUser.getSpotifyToken().getTokenExpiry()
        );

        originalSavedUser.getSpotifyToken().setRefreshToken("test-refresh-token-updated");
        originalSavedUser.getSpotifyToken().setAccessToken("test-access-token-updated");
        originalSavedUser.getSpotifyToken().setTokenExpiry(LocalDateTime.of(2025, 4, 4, 12, 30).toInstant(ZoneOffset.UTC));

        User updatedSavedUser = userRepository.save(user);

        assertNotNull(updatedSavedUser.getSpotifyToken());
        assertEquals("test-access-token-updated", updatedSavedUser.getSpotifyToken().getAccessToken());
        assertEquals("test-refresh-token-updated", updatedSavedUser.getSpotifyToken().getRefreshToken());
        assertEquals(
                LocalDateTime.of(2025, 4, 4, 12, 30).toInstant(ZoneOffset.UTC),
                updatedSavedUser.getSpotifyToken().getTokenExpiry()
        );
    }

    @Test
    void testFindUsersWithSpotifyTokenExpiringSoon() {
        User user = new User();
        user.setSpotifyUserId("testSpotifyUserId");
        user.setEmailAddress("test@email.address");
        user.setDisplayName("testDisplayName");

        SpotifyToken spotifyToken = new SpotifyToken();
        spotifyToken.setTokenExpiry(Instant.now().plusSeconds(60));
        spotifyToken.setAccessToken("test-access-token-original");
        spotifyToken.setRefreshToken("test-refresh-token-original");
        user.setSpotifyToken(spotifyToken);

        userRepository.save(user);

        List<User> usersWithTokensExpiringSoon = userRepository.findUsersWithSpotifyTokenExpiringSoon(
                Instant.now(),
                Instant.now().plusSeconds(300)
        );

        assertEquals(1, usersWithTokensExpiringSoon.size());
    }

    @Test
    void testFindUsersWithSpotifyTokenExpiringSoonNoUsersExist() {
        List<User> usersWithTokensExpiringSoon = userRepository.findUsersWithSpotifyTokenExpiringSoon(
                Instant.now(),
                Instant.now().plusSeconds(300)
        );

        assertTrue(usersWithTokensExpiringSoon.isEmpty());
    }

    @Test
    void testFindBySpotifyUserId() {
        User user = new User();
        user.setSpotifyUserId("testSpotifyUserId");
        user.setEmailAddress("test@email.address");
        user.setDisplayName("testDisplayName");
        userRepository.save(user);

        Optional<User> returnedUser = userRepository.findBySpotifyUserId("testSpotifyUserId");
        assertTrue(returnedUser.isPresent());
        assertEquals("testSpotifyUserId", returnedUser.get().getSpotifyUserId());
        assertEquals("test@email.address", returnedUser.get().getEmailAddress());
        assertEquals("testDisplayName", returnedUser.get().getDisplayName());
    }

    @Test
    void testFindBySpotifyUserIdNoUserExists() {
        Optional<User> user = userRepository.findBySpotifyUserId("testSpotifyUserId");
        assertTrue(user.isEmpty());
    }
}