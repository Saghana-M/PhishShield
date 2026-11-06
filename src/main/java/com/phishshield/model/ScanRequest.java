package com.phishshield.model;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Data Transfer Object (DTO) for receiving URL scan requests from the frontend.
 */
public class ScanRequest {

    @NotBlank(message = "Please enter a URL to scan.")
    @Size(max = 2048, message = "URL exceeds maximum permissible length of 2048 characters.")
    private String url;

    public ScanRequest() {
    }

    public ScanRequest(String url) {
        this.url = url;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }
}
