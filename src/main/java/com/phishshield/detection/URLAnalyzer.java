package com.phishshield.detection;

import com.phishshield.model.Finding;
import com.phishshield.model.URL;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Analyzes URL characteristics by running them through registered detection rules.
 * Demonstrates OOP Polymorphism by maintaining a collection of DetectionRule abstractions
 * and dynamically invoking each rule's evaluate() method at runtime.
 */
@Component
public class URLAnalyzer {

    // Polymorphism: List of DetectionRule interface instances
    private final List<DetectionRule> detectionRules;

    /**
     * Spring-managed constructor injecting all DetectionRule implementations.
     *
     * @param detectionRules polymorphic list of detection rules
     */
    @Autowired
    public URLAnalyzer(List<DetectionRule> detectionRules) {
        this.detectionRules = detectionRules != null ? new ArrayList<>(detectionRules) : new ArrayList<>();
    }

    /**
     * Default constructor for standalone manual usage or test scenarios.
     */
    public URLAnalyzer() {
        this.detectionRules = new ArrayList<>();
        this.detectionRules.add(new LongURLRule());
        this.detectionRules.add(new IPAddressRule());
        this.detectionRules.add(new SuspiciousKeywordRule());
        this.detectionRules.add(new SubdomainRule());
        this.detectionRules.add(new URLStructureRule());
    }

    /**
     * Analyzes the given URL against all registered detection rules.
     * Demonstrates Polymorphism in action: each rule is treated uniformly through
     * the DetectionRule interface, invoking its specific polymorphic implementation.
     *
     * @param url the encapsulated URL to analyze
     * @return a List of detected Findings (only rules that matched are returned)
     */
    public List<Finding> analyze(URL url) {
        if (url == null) {
            return Collections.emptyList();
        }

        List<Finding> matchedFindings = new ArrayList<>();

        for (DetectionRule rule : this.detectionRules) {
            Finding finding = rule.evaluate(url);
            if (finding != null) {
                matchedFindings.add(finding);
            }
        }

        return matchedFindings;
    }

    /**
     * Allows registering an additional detection rule dynamically.
     *
     * @param rule the DetectionRule to register
     */
    public void registerRule(DetectionRule rule) {
        if (rule != null) {
            this.detectionRules.add(rule);
        }
    }

    /**
     * Returns an unmodifiable view of all registered detection rules.
     *
     * @return list of detection rules
     */
    public List<DetectionRule> getDetectionRules() {
        return Collections.unmodifiableList(this.detectionRules);
    }
}
