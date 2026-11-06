package com.phishshield.detection;

import com.phishshield.model.Finding;
import com.phishshield.model.URL;

/**
 * Abstract parent class representing a baseline detection rule.
 * Demonstrates OOP Inheritance and Abstraction by providing common state,
 * encapsulated fields, and shared utility methods for specialized detection rules.
 */
public abstract class BaseDetectionRule implements DetectionRule {

    protected final String ruleName;
    protected final int points;
    protected final String description;

    /**
     * Protected constructor for subclasses.
     *
     * @param ruleName human-readable name of the rule
     * @param points risk points assigned on match
     * @param description summary explanation of what this rule detects
     */
    protected BaseDetectionRule(String ruleName, int points, String description) {
        this.ruleName = ruleName;
        this.points = points;
        this.description = description;
    }

    @Override
    public String getRuleName() {
        return ruleName;
    }

    @Override
    public int getPoints() {
        return points;
    }

    public String getDescription() {
        return description;
    }

    /**
     * Subclasses must implement the specific detection logic.
     *
     * @param url the encapsulated URL to inspect
     * @return Finding if matched, or null if no warning sign detected
     */
    @Override
    public abstract Finding evaluate(URL url);

    /**
     * Helper factory method to create a Finding instance when a rule matches.
     *
     * @param explanation detailed context-specific reason for the warning
     * @return populated Finding object
     */
    protected Finding createFinding(String explanation) {
        return new Finding(this.ruleName, this.points, explanation);
    }
}
