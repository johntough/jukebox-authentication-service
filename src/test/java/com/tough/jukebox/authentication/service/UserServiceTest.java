package com.tough.jukebox.authentication.service;

import com.tough.jukebox.authentication.model.SpotifyToken;
import com.tough.jukebox.authentication.model.User;
import com.tough.jukebox.authentication.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private UserService userService;

    @Test
    void testGetUserBySpotifyUserIdSuccess() {
        when(userRepository.findBySpotifyUserId(anyString())).thenReturn(Optional.of(new User()));

        Optional<User> user = userService.getUserBySpotifyUserId("test-spotify-user-id");

        assertTrue(user.isPresent());
    }

    @Test
    void testGetUserBySpotifyUserFailureIdNoUserFound() {
        when(userRepository.findBySpotifyUserId(anyString())).thenReturn(Optional.empty());

        Optional<User> user = userService.getUserBySpotifyUserId("test-spotify-user-id");

        assertTrue(user.isEmpty());
    }

    @Test
    void testGetUsersWithExpiringTokensSuccess() {
        List<User> userList = new ArrayList<>();
        userList.add(new User());

        when(userRepository.findUsersWithSpotifyTokenExpiringSoon(any(Instant.class), any(Instant.class))).thenReturn(userList);

        List<User> usersWithExpiringTokens = userService.getUsersWithExpiringTokens(
                Instant.now(),
                Instant.now().plusSeconds(300)
        );

        assertEquals( 1, usersWithExpiringTokens.size());
    }

    @Test
    void testGetUsersWithExpiringTokensNoUserFound() {

        when(userRepository.findUsersWithSpotifyTokenExpiringSoon(any(Instant.class), any(Instant.class))).thenReturn(new ArrayList<>());

        List<User> usersWithExpiringTokens = userService.getUsersWithExpiringTokens(
                Instant.now(),
                Instant.now().plusSeconds(300)
        );

        assertTrue(usersWithExpiringTokens.isEmpty());
    }

    @Test
    void testClearUserTokensSuccess() {
        when(userRepository.findBySpotifyUserId(anyString())).thenReturn(Optional.of(new User()));
        when(userRepository.save(any(User.class))).thenReturn(new User());

        boolean success = userService.clearUserTokens("test-spotify-user-id");

        assertTrue(success);
    }

    @Test
    void testClearUserTokensFailureNoUserFound() {
        when(userRepository.findBySpotifyUserId(anyString())).thenReturn(Optional.empty());

        boolean success = userService.clearUserTokens("test-spotify-user-id");

        assertFalse(success);
    }

    @Test
    void testUpdateUserTokensSuccess() {
        SpotifyToken spotifyToken = new SpotifyToken();
        spotifyToken.setRefreshToken("test-spotify-refresh-token");

        when(userRepository.save(any(User.class))).thenReturn(new User());

        userService.updateUserTokens(new User(), spotifyToken);

        verify(userRepository, times(1)).save(any(User.class));
    }
}
