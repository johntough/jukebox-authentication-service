package com.tough.jukebox.authentication.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Value(value = "${FRONT_END_REDIRECT}")
    private String frontendRedirectUri;

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }

    public String getFrontendRedirectUri() {
        return frontendRedirectUri;
    }

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        // This allows all endpoints to accept CORS requests from any origin.
        registry.addMapping("/**")
                .allowedOrigins("http://127.0.0.1:3000")
                .allowedMethods("GET", "POST", "PUT", "DELETE")
                .allowedHeaders("*")
                .allowCredentials(true)
                .maxAge(3600); // Cache the CORS preflight response for 1 hour
    }
}