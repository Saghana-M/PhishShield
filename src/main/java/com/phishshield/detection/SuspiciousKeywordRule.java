package com.phishshield.detection;

import com.phishshield.model.Finding;
import com.phishshield.model.URL;
import org.springframework.stereotype.Component;

import java.util.*;

/**
 * Detection Rule: Suspicious Keyword Combinations (+10 points).
 * Demonstrates OOP Inheritance by extending BaseDetectionRule.
 *
 * Phishing URLs frequently exploit security, credential-verification, and urgency keywords
 * (such as 'login', 'verify', 'account', 'banking', 'update', 'secure', 'password')
 * especially when combined with targeted brands or multiple high-risk tokens.
 */
@Component
public class SuspiciousKeywordRule extends BaseDetectionRule {

    // Common credential-harvesting, financial, and urgency keywords
    private static final Set<String> SENSITIVE_ACTION_KEYWORDS = Set.of(
            "login", "signin", "verify", "verification", "security", "secure",
            "update", "account", "banking", "wallet", "password", "credential",
            "authenticate", "confirm", "billing", "recover", "restore", "validate"
    );

    // Frequently targeted financial and technology brands often abused in phishing links
    private static final Set<String> HIGH_TARGET_BRANDS = Set.of(
            "paypal", "apple", "google", "microsoft", "amazon", "netflix",
            "chase", "wellsfargo", "bankofamerica", "binance", "coinbase", "meta", "facebook"
    );

    public SuspiciousKeywordRule() {
        super("Suspicious Keyword Combinations", 10, "Detects combinations of credential-harvesting, security, and brand keywords.");
    }

    @Override
    public Finding evaluate(URL url) {
        String fullUrl = (url.getRawUrl() != null ? url.getRawUrl() : "").toLowerCase(Locale.ROOT);
        String host = (url.getHost() != null ? url.getHost() : "").toLowerCase(Locale.ROOT);

        Set<String> matchedActions = new LinkedHashSet<>();
        Set<String> matchedBrands = new LinkedHashSet<>();

        for (String action : SENSITIVE_ACTION_KEYWORDS) {
            if (fullUrl.contains(action)) {
                matchedActions.add(action);
            }
        }

        for (String brand : HIGH_TARGET_BRANDS) {
            if (fullUrl.contains(brand)) {
                matchedBrands.add(brand);
            }
        }

        // Trigger condition:
        // 1. Two or more distinct sensitive action keywords (e.g., 'login' and 'verify', or 'secure' and 'account')
        // 2. OR at least one target brand combined with at least one sensitive action keyword
        boolean hasMultipleActions = matchedActions.size() >= 2;
        boolean hasBrandWithAction = !matchedBrands.isEmpty() && !matchedActions.isEmpty();

        if (hasMultipleActions || hasBrandWithAction) {
            List<String> allTokens = new ArrayList<>(matchedBrands);
            allTokens.addAll(matchedActions);

            String reasonDetail;
            if (hasBrandWithAction) {
                reasonDetail = String.format("A targeted brand name %s was detected alongside sensitive action keywords %s.",
                        matchedBrands, matchedActions);
            } else {
                reasonDetail = String.format("Multiple sensitive security/authentication keywords %s were detected.",
                        matchedActions);
            }

            String explanation = String.format(
                    "The URL contains suspicious keyword combinations: %s %s " +
                    "Phishing campaigns routinely chain sensitive terms (e.g., login, verify, banking, security) " +
                    "to simulate legitimate institutional workflows and deceive users into divulging credentials.",
                    allTokens, reasonDetail
            );

            return createFinding(explanation);
        }

        return null;
    }
}
