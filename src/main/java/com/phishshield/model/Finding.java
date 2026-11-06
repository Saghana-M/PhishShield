package com.phishshield.model;

/**
 * Represents an individual warning sign (finding) detected during a URL scan.
 * Stores the specific detection rule triggered, the risk points assigned,
 * and a clear human-readable explanation.
 */
public class Finding {

    private Long findingId;
    private Long scanId;
    private String ruleName;
    private int points;
    private String explanation;

    public Finding() {
    }

    public Finding(String ruleName, int points, String explanation) {
        this.ruleName = ruleName;
        this.points = points;
        this.explanation = explanation;
    }

    public Finding(Long findingId, Long scanId, String ruleName, int points, String explanation) {
        this.findingId = findingId;
        this.scanId = scanId;
        this.ruleName = ruleName;
        this.points = points;
        this.explanation = explanation;
    }

    // Encapsulation: Getters and Setters

    public Long getFindingId() {
        return findingId;
    }

    public void setFindingId(Long findingId) {
        this.findingId = findingId;
    }

    public Long getScanId() {
        return scanId;
    }

    public void setScanId(Long scanId) {
        this.scanId = scanId;
    }

    public String getRuleName() {
        return ruleName;
    }

    public void setRuleName(String ruleName) {
        this.ruleName = ruleName;
    }

    public int getPoints() {
        return points;
    }

    public void setPoints(int points) {
        this.points = points;
    }

    public String getExplanation() {
        return explanation;
    }

    public void setExplanation(String explanation) {
        this.explanation = explanation;
    }

    @Override
    public String toString() {
        return "Finding{" +
                "ruleName='" + ruleName + '\'' +
                ", points=" + points +
                ", explanation='" + explanation + '\'' +
                '}';
    }
}
