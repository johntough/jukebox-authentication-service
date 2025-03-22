package com.tough.jukebox.authentication.exceptions;

import org.springframework.http.HttpStatusCode;

public class VaultFailureException extends Exception {

    public VaultFailureException(String message) {
        super(message);
    }
}