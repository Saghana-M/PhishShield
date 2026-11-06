package com.phishshield.detection;

import com.phishshield.model.Finding;
import com.phishshield.model.URL;
import org.springframework.stereotype.Component;

/**
 * Detection Rule: Unusually Long URL (+10 points).
 * Demonstrates OOP Inheritance by extending BaseDetectionRule.
 *
 * Phishing URLs frequently exceed normal lengths to conceal malicious redirection
 * targets, embed nested encoded URLs, or evade signature-based detection.
 */
@Component
public class LongURLRule extends BaseDetectionRule {

    private static final int DEFAULT_LENGTH_THRESHOLD = 75;

    public LongURLRule() {
        super("Unusually Long URL", 10, "Detects URLs with excessive character length.");
    }

    @Override
    public Finding evaluate(URL url) {
        String raw = url.getRawUrl();
        if (raw == null) {
            return null;
        }

        int length = raw.length();
        if (length > DEFAULT_LENGTH_THRESHOLD) {
            String explanation = String.format(
                    "The URL length is %d characters, exceeding the normal heuristic threshold of %d characters. " +
                    "Attackers often construct abnormally long URLs to obscure the actual destination domain or append encoded redirect payloads.",
                    length, DEFAULT_LENGTH_THRESHOLD
            );
            return createFinding(explanation);
        }

        return null;
    }
}
