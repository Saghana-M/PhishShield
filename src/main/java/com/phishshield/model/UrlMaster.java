package com.phishshield.model;

import com.fasterxml.jackson.annotation.JsonFormat;

import java.time.LocalDateTime;

/**
 * Represents a persistent unique URL record stored in URL_MASTER.
 * Holds cumulative scan statistics and the most recent evaluation state.
 */
public class UrlMaster {

    private Long urlId;
    private String originalUrl;
    private String normalizedUrl;
    private int latestScore;
    private String latestStatus;

    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime firstSeen;

    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime lastSeen;

    private int totalScans;

    public UrlMaster() {
    }

    public UrlMaster(String originalUrl, String normalizedUrl, int latestScore, String latestStatus) {
        this.originalUrl = originalUrl;
        this.normalizedUrl = normalizedUrl;
        this.latestScore = latestScore;
        this.latestStatus = latestStatus;
        this.totalScans = 1;
        this.firstSeen = LocalDateTime.now();
        this.lastSeen = LocalDateTime.now();
    }

    public UrlMaster(Long urlId, String originalUrl, String normalizedUrl, int latestScore, String latestStatus, LocalDateTime firstSeen, LocalDateTime lastSeen, int totalScans) {
        this.urlId = urlId;
        this.originalUrl = originalUrl;
        this.normalizedUrl = normalizedUrl;
        this.latestScore = latestScore;
        this.latestStatus = latestStatus;
        this.firstSeen = firstSeen;
        this.lastSeen = lastSeen;
        this.totalScans = totalScans;
    }

    // Encapsulation: Getters and Setters

    public Long getUrlId() {
        return urlId;
    }

    public void setUrlId(Long urlId) {
        this.urlId = urlId;
    }

    public String getOriginalUrl() {
        return originalUrl;
    }

    public void setOriginalUrl(String originalUrl) {
        this.originalUrl = originalUrl;
    }

    public String getNormalizedUrl() {
        return normalizedUrl;
    }

    public void setNormalizedUrl(String normalizedUrl) {
        this.normalizedUrl = normalizedUrl;
    }

    public int getLatestScore() {
        return latestScore;
    }

    public void setLatestScore(int latestScore) {
        this.latestScore = latestScore;
    }

    public String getLatestStatus() {
        return latestStatus;
    }

    public void setLatestStatus(String latestStatus) {
        this.latestStatus = latestStatus;
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

    public int getTotalScans() {
        return totalScans;
    }

    public void setTotalScans(int totalScans) {
        this.totalScans = totalScans;
    }

    @Override
    public String toString() {
        return "UrlMaster{" +
                "urlId=" + urlId +
                ", normalizedUrl='" + normalizedUrl + '\'' +
                ", latestScore=" + latestScore +
                ", latestStatus='" + latestStatus + '\'' +
                ", totalScans=" + totalScans +
                '}';
    }
}
