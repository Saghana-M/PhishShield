package com.phishshield.detection;

import com.phishshield.model.Finding;
import com.phishshield.model.RiskCategory;
import com.phishshield.model.URL;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests verifying rule-based detection logic, polymorphism, and scoring.
 */
class DetectionRuleTest {

    private LongURLRule longURLRule;
    private IPAddressRule ipAddressRule;
    private SuspiciousKeywordRule keywordRule;
    private SubdomainRule subdomainRule;
    private URLStructureRule structureRule;
    private URLAnalyzer analyzer;
    private RiskScorer scorer;

    @BeforeEach
    void setUp() {
        longURLRule = new LongURLRule();
        ipAddressRule = new IPAddressRule();
        keywordRule = new SuspiciousKeywordRule();
        subdomainRule = new SubdomainRule();
        structureRule = new URLStructureRule();
        analyzer = new URLAnalyzer(List.of(longURLRule, ipAddressRule, keywordRule, subdomainRule, structureRule));
        scorer = new RiskScorer();
    }

    @Test
    @DisplayName("Normal URL triggers no warnings and scores Low Risk (0 points)")
    void testNormalUrl() {
        URL url = new URL("https://en.wikipedia.org/wiki/Computer_security");
        List<Finding> findings = analyzer.analyze(url);

        assertTrue(findings.isEmpty(), "Normal URL should not match any detection rules.");
        int score = scorer.calculateScore(findings);
        assertEquals(0, score);
        assertEquals(RiskCategory.LOW_RISK, scorer.classify(score));
    }

    @Test
    @DisplayName("Unusually long URL matches LongURLRule (+10 points)")
    void testLongUrlDetection() {
        String longUrlStr = "https://example.com/very/long/path/with/lots/of/parameters/and/tokens/that/exceeds/seventy/five/characters/token=" + "a".repeat(40);
        URL url = new URL(longUrlStr);

        Finding finding = longURLRule.evaluate(url);
        assertNotNull(finding);
        assertEquals("Unusually Long URL", finding.getRuleName());
        assertEquals(10, finding.getPoints());
    }

    @Test
    @DisplayName("IPv4 address as hostname matches IPAddressRule (+25 points)")
    void testIpAddressDetection() {
        URL url = new URL("http://192.168.1.100/index.html");

        Finding finding = ipAddressRule.evaluate(url);
        assertNotNull(finding);
        assertEquals("IP Address as Hostname", finding.getRuleName());
        assertEquals(25, finding.getPoints());
    }

    @Test
    @DisplayName("Suspicious keyword combinations trigger SuspiciousKeywordRule (+10 points)")
    void testSuspiciousKeywordsDetection() {
        // Contains targeted brand 'paypal' + action keyword 'verify'
        URL url = new URL("http://update-center.com/paypal/verify/account");

        Finding finding = keywordRule.evaluate(url);
        assertNotNull(finding);
        assertEquals("Suspicious Keyword Combinations", finding.getRuleName());
        assertEquals(10, finding.getPoints());
    }

    @Test
    @DisplayName("Deep subdomain nesting matches SubdomainRule (+15 points)")
    void testDeepSubdomainsDetection() {
        URL url = new URL("http://login.secure.portal.account.example.com/home");

        Finding finding = subdomainRule.evaluate(url);
        assertNotNull(finding);
        assertEquals("Unusual Subdomain Structure", finding.getRuleName());
        assertEquals(15, finding.getPoints());
    }

    @Test
    @DisplayName("Brand name in subdomain matches SubdomainRule (+15 points)")
    void testBrandInSubdomainDetection() {
        URL url = new URL("https://paypal.com.customer-support-portal.info/login");

        Finding finding = subdomainRule.evaluate(url);
        assertNotNull(finding);
        assertEquals("Unusual Subdomain Structure", finding.getRuleName());
        assertEquals(15, finding.getPoints());
    }

    @Test
    @DisplayName("Misleading structure with @ symbol and abnormal port matches URLStructureRule (+20 points)")
    void testUrlStructureDetection() {
        URL url = new URL("http://secure-login-portal.com:8443/account//confirm");

        Finding finding = structureRule.evaluate(url);
        assertNotNull(finding);
        assertEquals("Misleading URL Structure", finding.getRuleName());
        assertEquals(20, finding.getPoints());
    }

    @Test
    @DisplayName("High risk composite phishing URL triggers multiple rules and scores High Risk (>= 50)")
    void testCompositePhishingUrl() {
        // Combines IP address (+25), suspicious keywords (+10), misleading hyphenation & abnormal port (+20), excessive length (+10)
        String phishUrl = "http://192.168.1.50:8080/paypal-update-account/verify/login/portal?session=abcdef1234567890abcdef1234567890";
        URL url = new URL(phishUrl);

        List<Finding> findings = analyzer.analyze(url);
        assertFalse(findings.isEmpty());

        int score = scorer.calculateScore(findings);
        assertTrue(score >= 50, "Expected high risk score but got: " + score);
        assertEquals(RiskCategory.HIGH_RISK, scorer.classify(score));
    }
}
