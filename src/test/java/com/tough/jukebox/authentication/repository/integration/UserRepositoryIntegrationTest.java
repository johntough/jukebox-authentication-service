package com.tough.jukebox.authentication.repository.integration;

import com.tough.jukebox.authentication.model.User;
import com.tough.jukebox.authentication.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.ActiveProfiles;

import static org.junit.jupiter.api.Assertions.assertNotNull;

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
    }
}