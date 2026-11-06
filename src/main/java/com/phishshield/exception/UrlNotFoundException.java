package com.phishshield.exception;

/**
 * Exception thrown when a requested URL or Scan record is not found in the database.
 */
public class UrlNotFoundException extends RuntimeException {

    public UrlNotFoundException(String message) {
        super(message);
    }
}
