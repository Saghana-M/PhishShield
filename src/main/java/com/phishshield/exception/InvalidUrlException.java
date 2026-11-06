package com.phishshield.exception;

/**
 * Exception thrown when a submitted URL is invalid, malformed,
 * or does not adhere to supported schemes (HTTP/HTTPS).
 */
public class InvalidUrlException extends RuntimeException {

    public InvalidUrlException(String message) {
        super(message);
    }

    public InvalidUrlException(String message, Throwable cause) {
        super(message, cause);
    }
}
