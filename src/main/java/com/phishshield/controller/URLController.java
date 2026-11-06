package com.phishshield.controller;

import com.phishshield.model.Scan;
import com.phishshield.model.ScanRequest;
import com.phishshield.model.ScanResponse;
import com.phishshield.service.URLService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * REST Controller providing HTTP API endpoints for URL scanning,
 * scan history queries, and detailed finding inspections.
 */
@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*") // Allows local development and testing
public class URLController {

    private final URLService urlService;

    @Autowired
    public URLController(URLService urlService) {
        this.urlService = urlService;
    }

    /**
     * POST /api/scan
     * Validates and analyzes a submitted URL, executes detection rules, saves findings to MySQL,
     * and returns the comprehensive evaluation.
     *
     * @param request JSON payload containing the URL string
     * @return ScanResponse with score, classification, findings, and history
     */
    @PostMapping("/scan")
    public ResponseEntity<ScanResponse> scanUrl(@Valid @RequestBody ScanRequest request) {
        ScanResponse response = urlService.scanUrl(request.getUrl());
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    /**
     * GET /api/history
     * Retrieves a list of previously scanned URLs for the history view.
     *
     * @param limit optional limit (default 30)
     * @return list of Scan records
     */
    @GetMapping("/history")
    public ResponseEntity<List<Scan>> getScanHistory(
            @RequestParam(value = "limit", defaultValue = "30") int limit) {
        List<Scan> history = urlService.getRecentScans(limit);
        return ResponseEntity.ok(history);
    }

    /**
     * GET /api/history/{scanId}
     * Retrieves complete details of an individual scan including all warning signs detected.
     *
     * @param scanId ID of the scan
     * @return Scan record with populated findings
     */
    @GetMapping("/history/{scanId}")
    public ResponseEntity<Scan> getScanDetails(@PathVariable("scanId") Long scanId) {
        Scan scan = urlService.getScanDetails(scanId);
        return ResponseEntity.ok(scan);
    }

    /**
     * GET /api/url/{urlId}/history
     * Retrieves all historical scan events for a particular unique URL.
     *
     * @param urlId ID of the URL in URL_MASTER
     * @return list of historical scans for that URL
     */
    @GetMapping("/url/{urlId}/history")
    public ResponseEntity<List<Scan>> getUrlHistory(@PathVariable("urlId") Long urlId) {
        List<Scan> scans = urlService.getUrlScanHistory(urlId);
        return ResponseEntity.ok(scans);
    }

    /**
     * GET /api/stats
     * Retrieves aggregate summary metrics for the system.
     *
     * @return system statistics
     */
    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> getSystemStats() {
        Map<String, Object> stats = urlService.getSystemStatistics();
        return ResponseEntity.ok(stats);
    }
}
