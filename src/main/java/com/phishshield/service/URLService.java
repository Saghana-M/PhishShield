package com.phishshield.service;

import com.phishshield.detection.RiskScorer;
import com.phishshield.detection.URLAnalyzer;
import com.phishshield.exception.UrlNotFoundException;
import com.phishshield.model.*;
import com.phishshield.repository.URLRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;

/**
 * Service orchestrating the business logic of PhishShield.
 * Coordinates URL parsing, rule-based detection, risk calculation,
 * and transactional persistence across URL_MASTER, SCAN_HISTORY, and SCAN_FINDINGS.
 */
@Service
public class URLService {

    private static final Logger log = LoggerFactory.getLogger(URLService.class);

    private final URLAnalyzer urlAnalyzer;
    private final RiskScorer riskScorer;
    private final URLRepository urlRepository;

    @Autowired
    public URLService(URLAnalyzer urlAnalyzer, RiskScorer riskScorer, URLRepository urlRepository) {
        this.urlAnalyzer = urlAnalyzer;
        this.riskScorer = riskScorer;
        this.urlRepository = urlRepository;
    }

    /**
     * Executes a complete scan workflow for a submitted URL:
     * 1. Validates and encapsulates the URL.
     * 2. Checks URL_MASTER for prior submissions.
     * 3. Analyzes URL using rule engine (Polymorphism).
     * 4. Calculates heuristic risk score and status.
     * 5. Atomically persists URL_MASTER update/insert, SCAN_HISTORY, and SCAN_FINDINGS.
     * 6. Returns aggregated ScanResponse with historical context.
     *
     * @param rawUrl submitted raw URL string
     * @return ScanResponse containing results and history
     */
    @Transactional
    public ScanResponse scanUrl(String rawUrl) {
        log.info("Initiating scan for URL input: {}", rawUrl);

        // Step 1: Encapsulate and validate using URL object (checks scheme, host, syntax)
        URL url = new URL(rawUrl);

        // Step 2: Run heuristic detection rules via URLAnalyzer
        List<Finding> detectedFindings = urlAnalyzer.analyze(url);

        // Step 3: Compute risk score and classification
        int calculatedScore = riskScorer.calculateScore(detectedFindings);
        RiskCategory category = riskScorer.classify(calculatedScore);
        String status = category.getDisplayName();

        log.debug("URL: '{}' | Score: {} | Category: {} | Findings count: {}",
                url.getNormalizedUrl(), calculatedScore, status, detectedFindings.size());

        // Step 4: Check if normalized URL exists in URL_MASTER
        Optional<UrlMaster> existingMasterOpt = urlRepository.findByNormalizedUrl(url.getNormalizedUrl());

        Long urlId;
        boolean previouslyScanned;
        int totalScans;
        LocalDateTime firstSeen;
        LocalDateTime lastSeen;

        if (existingMasterOpt.isPresent()) {
            // Already exists in URL_MASTER: update record
            UrlMaster existing = existingMasterOpt.get();
            urlId = existing.getUrlId();
            previouslyScanned = true;
            firstSeen = existing.getFirstSeen();
            lastSeen = LocalDateTime.now();
            totalScans = existing.getTotalScans() + 1;

            urlRepository.updateUrlMasterOnRescan(urlId, calculatedScore, status);
            log.info("Existing URL identified (url_id: {}). Total scan count incremented to {}", urlId, totalScans);
        } else {
            // First time submission: insert into URL_MASTER
            UrlMaster newMaster = new UrlMaster(url.getRawUrl(), url.getNormalizedUrl(), calculatedScore, status);
            urlId = urlRepository.insertUrlMaster(newMaster);
            previouslyScanned = false;
            totalScans = 1;
            firstSeen = LocalDateTime.now();
            lastSeen = firstSeen;
            log.info("New unique URL registered in URL_MASTER with url_id: {}", urlId);
        }

        // Step 5: Insert record into SCAN_HISTORY
        Scan scan = new Scan(urlId, url.getRawUrl(), calculatedScore, status, LocalDateTime.now());
        Long scanId = urlRepository.insertScanHistory(scan);
        log.info("Scan record inserted into SCAN_HISTORY with scan_id: {}", scanId);

        // Step 6: Insert detected findings into SCAN_FINDINGS
        if (!detectedFindings.isEmpty()) {
            urlRepository.insertFindings(scanId, detectedFindings);
            log.debug("Saved {} warning findings for scan_id: {}", detectedFindings.size(), scanId);
        }

        // Step 7: Construct ScanResponse DTO
        ScanResponse response = new ScanResponse();
        response.setScanId(scanId);
        response.setUrlId(urlId);
        response.setSubmittedUrl(url.getRawUrl());
        response.setNormalizedUrl(url.getNormalizedUrl());
        response.setRiskScore(calculatedScore);
        response.setRiskClassification(status);
        response.setRiskDescription(category.getDescription());
        response.setBadgeClass(category.getBadgeClass());
        response.setScannedAt(scan.getScannedAt());
        response.setFindings(detectedFindings);

        response.setPreviouslyScanned(previouslyScanned);
        response.setTotalScans(totalScans);
        response.setFirstSeen(firstSeen);
        response.setLastSeen(lastSeen);

        return response;
    }

    /**
     * Retrieves recent scan history records with URL details.
     *
     * @param limit maximum records to fetch
     * @return list of recent scans
     */
    public List<Scan> getRecentScans(int limit) {
        int safeLimit = (limit > 0 && limit <= 100) ? limit : 20;
        return urlRepository.findRecentScans(safeLimit);
    }

    /**
     * Retrieves full details of an individual scan, including all detected findings.
     *
     * @param scanId scan ID
     * @return Scan object with populated findings
     */
    public Scan getScanDetails(Long scanId) {
        Scan scan = urlRepository.findScanById(scanId)
                .orElseThrow(() -> new UrlNotFoundException("Scan record with ID " + scanId + " not found."));

        List<Finding> findings = urlRepository.findFindingsByScanId(scanId);
        scan.setFindings(findings);
        return scan;
    }

    /**
     * Retrieves all historical scans for a specific URL ID.
     *
     * @param urlId URL ID
     * @return list of historical scans
     */
    public List<Scan> getUrlScanHistory(Long urlId) {
        UrlMaster master = urlRepository.findUrlById(urlId)
                .orElseThrow(() -> new UrlNotFoundException("URL with ID " + urlId + " not found in URL_MASTER."));

        List<Scan> scans = urlRepository.findScansByUrlId(urlId);
        for (Scan scan : scans) {
            scan.setFindings(urlRepository.findFindingsByScanId(scan.getScanId()));
            scan.setFirstSeen(master.getFirstSeen());
            scan.setLastSeen(master.getLastSeen());
            scan.setTotalPreviousScans(master.getTotalScans());
        }
        return scans;
    }

    /**
     * Aggregates system metrics (total scans, unique URLs, status distribution)
     * using SQL COUNT and GROUP BY queries.
     *
     * @return map of metrics
     */
    public Map<String, Object> getSystemStatistics() {
        Map<String, Object> stats = new LinkedHashMap<>();
        stats.put("totalScans", urlRepository.countTotalScans());
        stats.put("uniqueUrls", urlRepository.countUniqueUrls());
        stats.put("distribution", urlRepository.getRiskDistributionStats());
        return stats;
    }
}
