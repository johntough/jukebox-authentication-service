package com.tough.jukebox.authentication.repository;

import com.tough.jukebox.authentication.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, String> {

    Optional<User> findBySpotifyUserId(String spotifyUserId);

    @Query("SELECT u FROM User u " +
            "JOIN u.spotifyToken st " +
            "WHERE st.tokenExpiry BETWEEN :currentTime AND :fiveMinutesFromNow")
    List<User> findUsersWithSpotifyTokenExpiringSoon(Instant currentTime, Instant fiveMinutesFromNow);
}