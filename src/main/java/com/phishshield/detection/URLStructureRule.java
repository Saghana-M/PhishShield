package com.phishshield.detection;

import com.phishshield.model.Finding;
import com.phishshield.model.URL;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Detection Rule: Misleading URL Structure (+20 points).
 * Demonstrates OOP Inheritance by extending BaseDetectionRule.
 *
 * Attackers manipulate the syntactic structure of URLs to deceive users. Common tactics include:
 * - Embedding the '@' symbol (userinfo trickery where browsers disregard credentials before '@')
 * - Excessive hyphens in hostnames (typosquatting and prefix/suffix deception)
 * - Non-standard communication ports
 * - Obfuscated double slashes '//' in URL paths (open redirection tricks)
 */
@Component
public class URLStructureRule extends BaseDetectionRule {

    public URLStructureRule() {
        super("Misleading URL Structure", 20, "Detects misleading syntactic constructs such as '@' symbols, hyphen abuse, abnormal ports, or double slashes in paths.");
    }

    @Override
    public Finding evaluate(URL url) {
        String raw = url.getRawUrl() != null ? url.getRawUrl() : "";
        String host = url.getHost() != null ? url.getHost() : "";
        String path = url.getPath() != null ? url.getPath() : "";
        int port = url.getPort();

        List<String> detectedAnomalies = new ArrayList<>();

        // 1. Presence of '@' symbol
        if (raw.contains("@") || url.hasUserInfo()) {
            detectedAnomalies.add("Contains '@' symbol (used in phishing to trick the eye while directing traffic to the host following '@')");
        }

        // 2. Misleading hyphenation in domain (e.g., 'secure-bank-login.com' or 2+ hyphens)
        long hyphenCount = host.chars().filter(ch -> ch == '-').count();
        if (hyphenCount >= 2 || (hyphenCount >= 1 && (host.contains("login") || host.contains("secure") || host.contains("verify") || host.contains("update")))) {
            detectedAnomalies.add(String.format("Hostname contains deceptive hyphenation ('%s', %d hyphens) typical of typosquatting and fake brand portals", host, hyphenCount));
        }

        // 3. Non-standard ports (ports other than standard 80 for HTTP, 443 for HTTPS, and -1 default)
        if (port != -1 && port != 80 && port != 443) {
            detectedAnomalies.add(String.format("Uses non-standard port :%d (phishing kits and compromised hosts often run on obscure non-standard ports)", port));
        }

        // 4. Double slashes '//' in the path (open redirection vector)
        if (path.length() > 1 && path.substring(1).contains("//")) {
            detectedAnomalies.add("Path component contains consecutive double slashes ('//') often leveraged in open-redirection and filter-evasion exploits");
        }

        // 5. Percent-encoded characters in the authority/host (e.g., %2F, %40)
        if (host.contains("%")) {
            detectedAnomalies.add("Hostname contains percent-encoded hex characters intended to obscure the true domain name");
        }

        if (!detectedAnomalies.isEmpty()) {
            String explanation = String.format(
                    "The URL exhibits misleading structural anomalies: %s. " +
                    "These structural tricks manipulate URL syntax to disguise malicious destinations from human visual inspection.",
                    String.join("; ", detectedAnomalies)
            );
            return createFinding(explanation);
        }

        return null;
    }
}
