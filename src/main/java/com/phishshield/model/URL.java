package com.phishshield.model;

import com.phishshield.exception.InvalidUrlException;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;

/**
 * Represents a submitted URL within the PhishShield detection engine.
 * Demonstrates OOP Encapsulation with private fields, validation logic,
 * and component accessors.
 */
public class URL {

    private String rawUrl;
    private String normalizedUrl;
    private String scheme;
    private String host;
    private int port;
    private String path;
    private String query;
    private String userInfo;
    private URI uri;

    /**
     * Default constructor for serialization frameworks.
     */
    public URL() {
    }

    /**
     * Parameterized constructor that validates and parses the raw URL string.
     *
     * @param rawUrl the URL string submitted by the user
     * @throws InvalidUrlException if the URL is null, blank, malformed, or uses a non-HTTP(S) scheme
     */
    public URL(String rawUrl) {
        if (rawUrl == null || rawUrl.trim().isEmpty()) {
            throw new InvalidUrlException("URL cannot be empty. Please enter a valid HTTP or HTTPS URL.");
        }

        this.rawUrl = rawUrl.trim();
        parseAndValidate();
        this.normalizedUrl = computeNormalizedUrl();
    }

    /**
     * Validates the URL syntax using java.net.URI and verifies that only HTTP or HTTPS is used.
     */
    private void parseAndValidate() {
        try {
            // Pre-check for scheme: if missing, reject or fail validation
            this.uri = new URI(this.rawUrl);

            this.scheme = uri.getScheme();
            if (this.scheme == null) {
                throw new InvalidUrlException("Invalid URL: Missing protocol scheme. URLs must start with http:// or https://");
            }

            this.scheme = this.scheme.toLowerCase(Locale.ROOT);
            if (!this.scheme.equals("http") && !this.scheme.equals("https")) {
                throw new InvalidUrlException("Invalid URL scheme: Only 'http://' and 'https://' URLs are supported (received: " + this.scheme + ")");
            }

            this.host = uri.getHost();
            // In cases where host is null (e.g., malformed URI syntax like http:///test or http://:80), reject
            if (this.host == null || this.host.trim().isEmpty()) {
                throw new InvalidUrlException("Invalid URL: Hostname cannot be parsed or is missing.");
            }

            this.port = uri.getPort();
            this.path = uri.getPath() != null ? uri.getPath() : "";
            this.query = uri.getQuery();
            this.userInfo = uri.getUserInfo();

        } catch (URISyntaxException e) {
            throw new InvalidUrlException("Malformed URL syntax: " + e.getReason());
        }
    }

    /**
     * Computes a normalized representation of the URL to ensure consistent storage and deduplication
     * while carefully preserving full paths and query parameters.
     *
     * Normalization steps:
     * 1. Lowercase scheme and host.
     * 2. Remove default standard ports (80 for http, 443 for https).
     * 3. Normalize empty path to empty or single root slash.
     * 4. Exclude fragments (#anchor) as they are purely client-side.
     * 5. Preserve path and query parameters exactly as submitted.
     *
     * @return normalized URL string
     */
    private String computeNormalizedUrl() {
        StringBuilder sb = new StringBuilder();
        sb.append(this.scheme).append("://");

        if (this.userInfo != null && !this.userInfo.isEmpty()) {
            sb.append(this.userInfo).append("@");
        }

        sb.append(this.host.toLowerCase(Locale.ROOT));

        // Include port only if non-standard
        if (this.port != -1) {
            boolean isStandardHttp = "http".equals(this.scheme) && this.port == 80;
            boolean isStandardHttps = "https".equals(this.scheme) && this.port == 443;
            if (!isStandardHttp && !isStandardHttps) {
                sb.append(":").append(this.port);
            }
        }

        if (this.path != null && !this.path.isEmpty()) {
            sb.append(this.path);
        }

        if (this.query != null && !this.query.isEmpty()) {
            sb.append("?").append(this.query);
        }

        return sb.toString();
    }

    // Encapsulation: Getters and Setters

    public String getRawUrl() {
        return rawUrl;
    }

    public void setRawUrl(String rawUrl) {
        this.rawUrl = rawUrl;
    }

    public String getNormalizedUrl() {
        return normalizedUrl;
    }

    public void setNormalizedUrl(String normalizedUrl) {
        this.normalizedUrl = normalizedUrl;
    }

    public String getScheme() {
        return scheme;
    }

    public void setScheme(String scheme) {
        this.scheme = scheme;
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public String getQuery() {
        return query;
    }

    public void setQuery(String query) {
        this.query = query;
    }

    public String getUserInfo() {
        return userInfo;
    }

    public void setUserInfo(String userInfo) {
        this.userInfo = userInfo;
    }

    public URI getUri() {
        return uri;
    }

    public void setUri(URI uri) {
        this.uri = uri;
    }

    public boolean isHttps() {
        return "https".equalsIgnoreCase(this.scheme);
    }

    public boolean hasUserInfo() {
        return this.userInfo != null && !this.userInfo.trim().isEmpty();
    }

    @Override
    public String toString() {
        return "URL{" +
                "rawUrl='" + rawUrl + '\'' +
                ", normalizedUrl='" + normalizedUrl + '\'' +
                ", host='" + host + '\'' +
                '}';
    }
}
