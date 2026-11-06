package com.phishshield.detection;

import com.phishshield.model.Finding;
import com.phishshield.model.URL;
import org.springframework.stereotype.Component;

import java.util.Locale;
import java.util.Set;

/**
 * Detection Rule: Unusual Subdomain Structure (+15 points).
 * Demonstrates OOP Inheritance by extending BaseDetectionRule.
 *
 * Attackers frequently manipulate subdomains to mimic legitimate brand domains
 * (e.g., 'paypal.com.verify-accounts.net') or stack deep subdomains
 * (e.g., 'a.b.c.d.evil.com') to confuse users and obscure the true apex domain.
 */
@Component
public class SubdomainRule extends BaseDetectionRule {

    private static final int MAX_EXPECTED_DOTS = 2; // e.g., 'sub.domain.com' has 2 dots (3 parts)

    private static final Set<String> HIGH_PROFILE_BRANDS = Set.of(
            "paypal", "apple", "google", "microsoft", "amazon", "netflix",
            "facebook", "instagram", "chase", "wellsfargo", "bankofamerica"
    );

    public SubdomainRule() {
        super("Unusual Subdomain Structure", 15, "Detects deep subdomain nesting or misleading brand names embedded in subdomains.");
    }

    @Override
    public Finding evaluate(URL url) {
        String host = url.getHost();
        if (host == null || host.trim().isEmpty()) {
            return null;
        }

        String lowerHost = host.toLowerCase(Locale.ROOT);
        String[] parts = lowerHost.split("\\.");

        // If host has 4 or more parts (3 or more dots), e.g., 'login.security.portal.example.com'
        int dotCount = 0;
        for (char c : lowerHost.toCharArray()) {
            if (c == '.') {
                dotCount++;
            }
        }

        boolean excessiveSubdomains = dotCount > MAX_EXPECTED_DOTS;

        // Check if any brand name is used as an artificial subdomain while the root domain is different
        // E.g., 'paypal.com.phishingsite.net' or 'apple.id.fake.org'
        boolean brandInSubdomain = false;
        String matchedBrand = null;

        if (parts.length >= 3) {
            // Apex domain is usually the last 2 parts (e.g. example.com)
            // Subdomain portion comprises parts before the last 2 parts
            StringBuilder subdomains = new StringBuilder();
            for (int i = 0; i < parts.length - 2; i++) {
                subdomains.append(parts[i]).append(" ");
            }
            String subdomainString = subdomains.toString();

            for (String brand : HIGH_PROFILE_BRANDS) {
                if (subdomainString.contains(brand)) {
                    // Make sure the apex domain isn't actually the brand itself (e.g., not 'paypal.com' or 'google.com')
                    String apex = parts[parts.length - 2] + "." + parts[parts.length - 1];
                    if (!apex.contains(brand)) {
                        brandInSubdomain = true;
                        matchedBrand = brand;
                        break;
                    }
                }
            }
        }

        if (excessiveSubdomains || brandInSubdomain) {
            String explanation;
            if (brandInSubdomain) {
                explanation = String.format(
                        "The hostname '%s' embeds a well-known brand name ('%s') inside a subdomain level, " +
                        "while the true destination domain is different. This is a classic subdomain spoofing technique " +
                        "designed to trick users into trusting a fraudulent site.",
                        host, matchedBrand
                );
            } else {
                explanation = String.format(
                        "The hostname '%s' contains %d subdomain levels (%d dots), which exceeds standard domain architectures. " +
                        "Phishers frequently chain multiple subdomain tiers to push the actual registered domain out of view " +
                        "in mobile browser address bars.",
                        host, dotCount, dotCount
                );
            }

            return createFinding(explanation);
        }

        return null;
    }
}
