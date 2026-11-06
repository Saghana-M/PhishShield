package com.phishshield.model;

import com.fasterxml.jackson.annotation.JsonFormat;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * Represents an individual scan execution in PhishShield.
 * Holds the evaluated risk score, classification status, timestamp,
 * and list of detected findings (warning signs).
 */
public class Scan {

    private Long scanId;
    private Long urlId;
    private String scannedUrl;
    private int scanScore;
    private String scanStatus;

    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime scannedAt;

    private List<Finding> findings = new ArrayList<>();

    // Historical context from URL_MASTER
    private int totalPreviousScans;
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime firstSeen;
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime lastSeen;

    public Scan() {
    }

    public Scan(Long urlId, String scannedUrl, int scanScore, String scanStatus, LocalDateTime scannedAt) {
        this.urlId = urlId;
        this.scannedUrl = scannedUrl;
        this.scanScore = scanScore;
        this.scanStatus = scanStatus;
        this.scannedAt = scannedAt;
    }

    public Scan(Long scanId, Long urlId, String scannedUrl, int scanScore, String scanStatus, LocalDateTime scannedAt) {
        this.scanId = scanId;
        this.urlId = urlId;
        this.scannedUrl = scannedUrl;
        this.scanScore = scanScore;
        this.scanStatus = scanStatus;
        this.scannedAt = scannedAt;
    }

    // Encapsulation: Getters and Setters

    public Long getScanId() {
        return scanId;
    }

    public void setScanId(Long scanId) {
        this.scanId = scanId;
    }

    public Long getUrlId() {
        return urlId;
    }

    public void setUrlId(Long urlId) {
        this.urlId = urlId;
    }

    public String getScannedUrl() {
        return scannedUrl;
    }

    public void setScannedUrl(String scannedUrl) {
        this.scannedUrl = scannedUrl;
    }

    public int getScanScore() {
        return scanScore;
    }

    public void setScanScore(int scanScore) {
        this.scanScore = scanScore;
    }

    public String getScanStatus() {
        return scanStatus;
    }

    public void setScanStatus(String scanStatus) {
        this.scanStatus = scanStatus;
    }

    public LocalDateTime getScannedAt() {
        return scannedAt;
    }

    public void setScannedAt(LocalDateTime scannedAt) {
        this.scannedAt = scannedAt;
    }

    public List<Finding> getFindings() {
        return findings;
    }

    public void setFindings(List<Finding> findings) {
        this.findings = findings;
    }

    public void addFinding(Finding finding) {
        if (this.findings == null) {
            this.findings = new ArrayList<>();
        }
        this.findings.add(finding);
    }

    public int getTotalPreviousScans() {
        return totalPreviousScans;
    }

    public void setTotalPreviousScans(int totalPreviousScans) {
        this.totalPreviousScans = totalPreviousScans;
    }

    public LocalDateTime getFirstSeen() {
        return firstSeen;
    }

    public void setFirstSeen(LocalDateTime firstSeen) {
        this.firstSeen = firstSeen;
    }

    public LocalDateTime getLastSeen() {
        return lastSeen;
    }

    public void setLastSeen(LocalDateTime lastSeen) {
        this.lastSeen = lastSeen;
    }

    @Override
    public String toString() {
        return "Scan{" +
                "scanId=" + scanId +
                ", scannedUrl='" + scannedUrl + '\'' +
                ", scanScore=" + scanScore +
                ", scanStatus='" + scanStatus + '\'' +
                ", scannedAt=" + scannedAt +
                ", findingsCount=" + (findings != null ? findings.size() : 0) +
                '}';
    }
}
