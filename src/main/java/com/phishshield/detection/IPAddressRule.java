package com.phishshield.detection;

import com.phishshield.model.Finding;
import com.phishshield.model.URL;
import org.springframework.stereotype.Component;

import java.util.regex.Pattern;

/**
 * Detection Rule: IP Address as Hostname (+25 points).
 * Demonstrates OOP Inheritance by extending BaseDetectionRule.
 *
 * Legitimate web services and financial institutions use registered domain names.
 * Using an IP address directly in the authority component allows attackers to bypass
 * domain registration scrutiny, brand-name lookup, and domain reputation systems.
 */
@Component
public class IPAddressRule extends BaseDetectionRule {

    // Regex for standard IPv4 dotted-decimal address
    private static final Pattern IPV4_PATTERN = Pattern.compile(
            "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    );

    // Regex for IPv6 or hex-encoded / octal-encoded host representation
    private static final Pattern IPV6_PATTERN = Pattern.compile(
            "^(\\[?[0-9a-fA-F:]+\\]?)$"
    );

    public IPAddressRule() {
        super("IP Address as Hostname", 25, "Detects numerical IP addresses used instead of registered domain names.");
    }

    @Override
    public Finding evaluate(URL url) {
        String host = url.getHost();
        if (host == null || host.trim().isEmpty()) {
            return null;
        }

        // Strip enclosing square brackets if IPv6
        String cleanHost = host.replaceAll("^\\[|\\]$", "").trim();

        boolean isIpv4 = IPV4_PATTERN.matcher(cleanHost).matches();
        boolean isIpv6 = cleanHost.contains(":") && IPV6_PATTERN.matcher(cleanHost).matches();

        if (isIpv4 || isIpv6) {
            String explanation = String.format(
                    "The hostname '%s' is a raw numerical IP address (%s) instead of a registered domain name. " +
                    "Legitimate commercial and institutional platforms rarely present raw IP addresses to users; " +
                    "attackers use them to bypass domain reputation blocklists and registrar registration records.",
                    host, isIpv4 ? "IPv4" : "IPv6"
            );
            return createFinding(explanation);
        }

        return null;
    }
}
