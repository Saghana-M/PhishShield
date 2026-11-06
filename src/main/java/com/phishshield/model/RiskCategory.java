package com.phishshield.model;

/**
 * Enumeration representing the three risk classifications in PhishShield.
 * Heuristic prototype thresholds:
 * - 0–19: Low Risk
 * - 20–49: Suspicious
 * - 50–100: High Risk
 */
public enum RiskCategory {
    LOW_RISK("Low Risk", 0, 19, "Few or no suspicious characteristics detected. Exercise standard vigilance.", "success"),
    SUSPICIOUS("Suspicious", 20, 49, "Multiple suspicious indicators detected. Exercise caution before trusting this link.", "warning"),
    HIGH_RISK("High Risk", 50, 100, "Strong indicators of deceptive or phishing URL patterns detected. Avoid interacting with this link.", "danger");

    private final String displayName;
    private final int minScore;
    private final int maxScore;
    private final String description;
    private final String badgeClass;

    RiskCategory(String displayName, int minScore, int maxScore, String description, String badgeClass) {
        this.displayName = displayName;
        this.minScore = minScore;
        this.maxScore = maxScore;
        this.description = description;
        this.badgeClass = badgeClass;
    }

    public String getDisplayName() {
        return displayName;
    }

    public int getMinScore() {
        return minScore;
    }

    public int getMaxScore() {
        return maxScore;
    }

    public String getDescription() {
        return description;
    }

    public String getBadgeClass() {
        return badgeClass;
    }

    /**
     * Determines the risk category corresponding to an integer score.
     *
     * @param score numeric risk score (0-100)
     * @return the appropriate RiskCategory
     */
    public static RiskCategory fromScore(int score) {
        if (score <= 19) {
            return LOW_RISK;
        } else if (score <= 49) {
            return SUSPICIOUS;
        } else {
            return HIGH_RISK;
        }
    }
}
