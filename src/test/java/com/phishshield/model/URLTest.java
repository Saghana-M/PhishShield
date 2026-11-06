package com.phishshield.model;

import com.phishshield.exception.InvalidUrlException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests verifying URL parsing, encapsulation, validation, and normalization.
 */
class URLTest {

    @Test
    @DisplayName("Valid HTTPS URL parses correctly with all components encapsulated")
    void testValidHttpsUrl() {
        URL url = new URL("https://example.com/login?token=abc");

        assertEquals("https", url.getScheme());
        assertEquals("example.com", url.getHost());
        assertEquals("/login", url.getPath());
        assertEquals("token=abc", url.getQuery());
        assertTrue(url.isHttps());
        assertFalse(url.hasUserInfo());
        assertEquals("https://example.com/login?token=abc", url.getNormalizedUrl());
    }

    @Test
    @DisplayName("Standard port 443 on HTTPS is stripped during normalization")
    void testStandardPortNormalization() {
        URL url = new URL("https://Example.COM:443/portal/index.html?ref=mail");

        assertEquals("https://example.com/portal/index.html?ref=mail", url.getNormalizedUrl());
    }

    @Test
    @DisplayName("Non-standard port is preserved during normalization")
    void testNonStandardPortPreserved() {
        URL url = new URL("http://example.com:8080/api/auth");

        assertEquals("http://example.com:8080/api/auth", url.getNormalizedUrl());
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "",
            "   ",
            "ftp://files.example.com/doc.pdf",
            "javascript:alert(1)",
            "data:text/html,hello",
            "file:///C:/passwords.txt",
            "not-a-valid-url",
            "http://:8080"
    })
    @DisplayName("Rejects invalid URLs, non-HTTP/HTTPS schemes, or empty input")
    void testInvalidUrlsThrowException(String invalidUrl) {
        assertThrows(InvalidUrlException.class, () -> new URL(invalidUrl));
    }
}
