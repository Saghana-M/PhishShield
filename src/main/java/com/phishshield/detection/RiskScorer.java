package com.phishshield.detection;

import com.phishshield.model.Finding;
import com.phishshield.model.RiskCategory;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Calculates the final risk score from a collection of detected findings
 * and determines the corresponding risk classification.
 *
 * Scoring specifications:
 * - Unusually long URL: +10
 * - IP address as hostname: +25
 * - Suspicious keyword combinations: +10
 * - Unusual subdomain structure: +15
 * - Misleading URL structure: +20
 *
 * Total score is capped at 100.
 * Classifications:
 * - 0–19: Low Risk
 * - 20–49: Suspicious
 * - 50–100: High Risk
 */
@Component
public class RiskScorer {

    private static final int MAX_SCORE = 100;

    /**
     * Calculates the cumulative risk score by summing the points of all triggered findings.
     * Capped at 100.
     *
     * @param findings list of identified warning signs
     * @return aggregated score between 0 and 100
     */
    public int calculateScore(List<Finding> findings) {
        if (findings == null || findings.isEmpty()) {
            return 0;
        }

        int total = 0;
        for (Finding finding : findings) {
            total += finding.getPoints();
        }

        return Math.min(total, MAX_SCORE);
    }

    /**
     * Determines the risk classification for a calculated score.
     *
     * @param score numeric risk score
     * @return corresponding RiskCategory
     */
    public RiskCategory classify(int score) {
        return RiskCategory.fromScore(score);
    }
}
