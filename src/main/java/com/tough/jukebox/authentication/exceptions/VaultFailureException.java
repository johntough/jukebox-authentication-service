package com.tough.jukebox.authentication.exceptions;

import org.springframework.http.HttpStatusCode;

public class VaultFailureException extends Exception {

    private final HttpStatusCode statusCode;

    public VaultFailureException(String message, HttpStatusCode statusCode) {
        super(message);
        this.statusCode = statusCode;
    }

    public HttpStatusCode getStatusCode() {
        return statusCode;
    }
}