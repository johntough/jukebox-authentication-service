package com.tough.jukebox.authentication.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    private final JwtUtil jwtUtil;

    @Autowired
    public JwtAuthenticationFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String requestURI = request.getRequestURI();

        if (requestURI.startsWith("/auth/spotifyAuthorizationCallback") || requestURI.startsWith("/auth/spotifyRedirectParams")) {
            filterChain.doFilter(request, response);
        } else {
            String token = extractTokenFromRequest(request);

            if (token != null && jwtUtil.validateToken(token)) {
                request.setAttribute("userId", jwtUtil.getUserIdFromToken(token));
                request.setAttribute("jwt", token);
                filterChain.doFilter(request, response);
            } else {
                LOGGER.info("JWT validation failed for {}, returning 401 UNAUTHORIZED.", requestURI);
                response.setHeader("Access-Control-Allow-Origin", "http://127.0.0.1:3000");  // Adjust the frontend URL as needed
                response.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");  // Allow methods
                response.setHeader("Access-Control-Allow-Headers", "*");  // Allow all headers
                response.setHeader("Access-Control-Allow-Credentials", "true");
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            }
        }
    }

    private String extractTokenFromRequest(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();

        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("jwt".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }
}