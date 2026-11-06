package com.phishshield.detection;

import com.phishshield.model.Finding;
import com.phishshield.model.URL;

/**
 * Interface defining common behaviour for URL phishing detection rules.
 * Demonstrates OOP Abstraction by decoupling the analysis contract from
 * specific heuristic implementations.
 */
public interface DetectionRule {

    /**
     * Evaluates a URL against this detection rule.
     *
     * @param url the encapsulated URL object to evaluate
     * @return a Finding object containing details if a warning sign was detected,
     *         or null if the rule criteria was not met.
     */
    Finding evaluate(URL url);

    /**
     * Gets the unique human-readable name of the detection rule.
     *
     * @return rule name
     */
    String getRuleName();

    /**
     * Gets the risk points assigned when this rule matches.
     *
     * @return points assigned to this rule
     */
    int getPoints();
}
