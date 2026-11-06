package com.phishshield.repository;

import com.phishshield.exception.DatabaseOperationException;
import com.phishshield.model.Finding;
import com.phishshield.model.Scan;
import com.phishshield.model.UrlMaster;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.jdbc.support.KeyHolder;
import org.springframework.stereotype.Repository;

import java.sql.PreparedStatement;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.*;

/**
 * Data Access Repository for PhishShield using Spring JdbcTemplate.
 * Implements parameterized queries, transaction support, table joins,
 * aggregate COUNT queries, and GROUP BY statistics.
 */
@Repository
public class URLRepository {

    private final JdbcTemplate jdbcTemplate;

    @Autowired
    public URLRepository(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    // -------------------------------------------------------------------------
    // Row Mappers
    // -------------------------------------------------------------------------

    private final RowMapper<UrlMaster> urlMasterRowMapper = (rs, rowNum) -> {
        UrlMaster master = new UrlMaster();
        master.setUrlId(rs.getLong("url_id"));
        master.setOriginalUrl(rs.getString("original_url"));
        master.setNormalizedUrl(rs.getString("normalized_url"));
        master.setLatestScore(rs.getInt("latest_score"));
        master.setLatestStatus(rs.getString("latest_status"));
        Timestamp firstSeenTs = rs.getTimestamp("first_seen");
        master.setFirstSeen(firstSeenTs != null ? firstSeenTs.toLocalDateTime() : null);
        Timestamp lastSeenTs = rs.getTimestamp("last_seen");
        master.setLastSeen(lastSeenTs != null ? lastSeenTs.toLocalDateTime() : null);
        master.setTotalScans(rs.getInt("total_scans"));
        return master;
    };

    private final RowMapper<Scan> scanRowMapper = (rs, rowNum) -> {
        Scan scan = new Scan();
        scan.setScanId(rs.getLong("scan_id"));
        scan.setUrlId(rs.getLong("url_id"));
        scan.setScannedUrl(rs.getString("scanned_url"));
        scan.setScanScore(rs.getInt("scan_score"));
        scan.setScanStatus(rs.getString("scan_status"));
        Timestamp scannedAtTs = rs.getTimestamp("scanned_at");
        scan.setScannedAt(scannedAtTs != null ? scannedAtTs.toLocalDateTime() : null);
        return scan;
    };

    private final RowMapper<Finding> findingRowMapper = (rs, rowNum) -> {
        Finding finding = new Finding();
        finding.setFindingId(rs.getLong("finding_id"));
        finding.setScanId(rs.getLong("scan_id"));
        finding.setRuleName(rs.getString("rule_name"));
        finding.setPoints(rs.getInt("points"));
        finding.setExplanation(rs.getString("explanation"));
        return finding;
    };

    // -------------------------------------------------------------------------
    // URL_MASTER Operations (INSERT, SELECT, UPDATE)
    // -------------------------------------------------------------------------

    /**
     * Looks up a URL record in URL_MASTER by its normalized URL string.
     *
     * @param normalizedUrl normalized URL
     * @return Optional containing the UrlMaster if found
     */
    public Optional<UrlMaster> findByNormalizedUrl(String normalizedUrl) {
        String sql = "SELECT url_id, original_url, normalized_url, latest_score, latest_status, first_seen, last_seen, total_scans " +
                     "FROM url_master WHERE normalized_url = ?";
        try {
            List<UrlMaster> results = jdbcTemplate.query(sql, urlMasterRowMapper, normalizedUrl);
            return results.stream().findFirst();
        } catch (DataAccessException e) {
            throw new DatabaseOperationException("Failed to query URL_MASTER by normalized URL: " + e.getMessage(), e);
        }
    }

    /**
     * Finds a URL record in URL_MASTER by primary key.
     *
     * @param urlId URL ID
     * @return Optional containing the UrlMaster
     */
    public Optional<UrlMaster> findUrlById(Long urlId) {
        String sql = "SELECT url_id, original_url, normalized_url, latest_score, latest_status, first_seen, last_seen, total_scans " +
                     "FROM url_master WHERE url_id = ?";
        try {
            List<UrlMaster> results = jdbcTemplate.query(sql, urlMasterRowMapper, urlId);
            return results.stream().findFirst();
        } catch (DataAccessException e) {
            throw new DatabaseOperationException("Failed to find URL by ID: " + e.getMessage(), e);
        }
    }

    /**
     * Inserts a new unique URL record into URL_MASTER.
     *
     * @param master UrlMaster entity
     * @return the generated url_id primary key
     */
    public Long insertUrlMaster(UrlMaster master) {
        String sql = "INSERT INTO url_master (original_url, normalized_url, latest_score, latest_status, first_seen, last_seen, total_scans) " +
                     "VALUES (?, ?, ?, ?, NOW(), NOW(), 1)";
        try {
            KeyHolder keyHolder = new GeneratedKeyHolder();
            jdbcTemplate.update(connection -> {
                PreparedStatement ps = connection.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS);
                ps.setString(1, master.getOriginalUrl());
                ps.setString(2, master.getNormalizedUrl());
                ps.setInt(3, master.getLatestScore());
                ps.setString(4, master.getLatestStatus());
                return ps;
            }, keyHolder);

            Number key = keyHolder.getKey();
            if (key == null) {
                throw new DatabaseOperationException("Failed to retrieve generated primary key for URL_MASTER.");
            }
            master.setUrlId(key.longValue());
            return master.getUrlId();
        } catch (DataAccessException e) {
            throw new DatabaseOperationException("Failed to insert into URL_MASTER: " + e.getMessage(), e);
        }
    }

    /**
     * Updates URL_MASTER upon repeated scans of an existing URL.
     * Updates latest_score, latest_status, last_seen timestamp, and increments total_scans.
     *
     * @param urlId URL ID primary key
     * @param latestScore new evaluated risk score
     * @param latestStatus new evaluated risk classification
     */
    public void updateUrlMasterOnRescan(Long urlId, int latestScore, String latestStatus) {
        String sql = "UPDATE url_master " +
                     "SET latest_score = ?, latest_status = ?, last_seen = NOW(), total_scans = total_scans + 1 " +
                     "WHERE url_id = ?";
        try {
            jdbcTemplate.update(sql, latestScore, latestStatus, urlId);
        } catch (DataAccessException e) {
            throw new DatabaseOperationException("Failed to update URL_MASTER on rescan: " + e.getMessage(), e);
        }
    }

    // -------------------------------------------------------------------------
    // SCAN_HISTORY Operations (INSERT, SELECT with JOIN)
    // -------------------------------------------------------------------------

    /**
     * Inserts an individual scan record into SCAN_HISTORY.
     *
     * @param scan Scan entity
     * @return the generated scan_id primary key
     */
    public Long insertScanHistory(Scan scan) {
        String sql = "INSERT INTO scan_history (url_id, scanned_url, scan_score, scan_status, scanned_at) " +
                     "VALUES (?, ?, ?, ?, NOW())";
        try {
            KeyHolder keyHolder = new GeneratedKeyHolder();
            jdbcTemplate.update(connection -> {
                PreparedStatement ps = connection.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS);
                ps.setLong(1, scan.getUrlId());
                ps.setString(2, scan.getScannedUrl());
                ps.setInt(3, scan.getScanScore());
                ps.setString(4, scan.getScanStatus());
                return ps;
            }, keyHolder);

            Number key = keyHolder.getKey();
            if (key == null) {
                throw new DatabaseOperationException("Failed to retrieve generated primary key for SCAN_HISTORY.");
            }
            scan.setScanId(key.longValue());
            return scan.getScanId();
        } catch (DataAccessException e) {
            throw new DatabaseOperationException("Failed to insert into SCAN_HISTORY: " + e.getMessage(), e);
        }
    }

    /**
     * Retrieves an individual scan by scan_id along with parent URL_MASTER statistics.
     * Demonstrates SQL JOIN between SCAN_HISTORY and URL_MASTER.
     *
     * @param scanId scan ID
     * @return Optional containing the fully populated Scan
     */
    public Optional<Scan> findScanById(Long scanId) {
        String sql = "SELECT h.scan_id, h.url_id, h.scanned_url, h.scan_score, h.scan_status, h.scanned_at, " +
                     "       m.first_seen, m.last_seen, m.total_scans " +
                     "FROM scan_history h " +
                     "JOIN url_master m ON h.url_id = m.url_id " +
                     "WHERE h.scan_id = ?";

        try {
            List<Scan> results = jdbcTemplate.query(sql, (rs, rowNum) -> {
                Scan scan = new Scan();
                scan.setScanId(rs.getLong("scan_id"));
                scan.setUrlId(rs.getLong("url_id"));
                scan.setScannedUrl(rs.getString("scanned_url"));
                scan.setScanScore(rs.getInt("scan_score"));
                scan.setScanStatus(rs.getString("scan_status"));
                Timestamp scannedAtTs = rs.getTimestamp("scanned_at");
                scan.setScannedAt(scannedAtTs != null ? scannedAtTs.toLocalDateTime() : null);

                Timestamp firstSeenTs = rs.getTimestamp("first_seen");
                scan.setFirstSeen(firstSeenTs != null ? firstSeenTs.toLocalDateTime() : null);
                Timestamp lastSeenTs = rs.getTimestamp("last_seen");
                scan.setLastSeen(lastSeenTs != null ? lastSeenTs.toLocalDateTime() : null);
                scan.setTotalPreviousScans(rs.getInt("total_scans"));

                return scan;
            }, scanId);

            return results.stream().findFirst();
        } catch (DataAccessException e) {
            throw new DatabaseOperationException("Failed to find scan by ID: " + e.getMessage(), e);
        }
    }

    /**
     * Retrieves recent scan history with JOIN to URL_MASTER for full context.
     *
     * @param limit maximum records to retrieve
     * @return list of recent scans
     */
    public List<Scan> findRecentScans(int limit) {
        String sql = "SELECT h.scan_id, h.url_id, h.scanned_url, h.scan_score, h.scan_status, h.scanned_at, " +
                     "       m.first_seen, m.last_seen, m.total_scans " +
                     "FROM scan_history h " +
                     "JOIN url_master m ON h.url_id = m.url_id " +
                     "ORDER BY h.scanned_at DESC " +
                     "LIMIT ?";

        try {
            return jdbcTemplate.query(sql, (rs, rowNum) -> {
                Scan scan = new Scan();
                scan.setScanId(rs.getLong("scan_id"));
                scan.setUrlId(rs.getLong("url_id"));
                scan.setScannedUrl(rs.getString("scanned_url"));
                scan.setScanScore(rs.getInt("scan_score"));
                scan.setScanStatus(rs.getString("scan_status"));
                Timestamp scannedAtTs = rs.getTimestamp("scanned_at");
                scan.setScannedAt(scannedAtTs != null ? scannedAtTs.toLocalDateTime() : null);

                Timestamp firstSeenTs = rs.getTimestamp("first_seen");
                scan.setFirstSeen(firstSeenTs != null ? firstSeenTs.toLocalDateTime() : null);
                Timestamp lastSeenTs = rs.getTimestamp("last_seen");
                scan.setLastSeen(lastSeenTs != null ? lastSeenTs.toLocalDateTime() : null);
                scan.setTotalPreviousScans(rs.getInt("total_scans"));

                return scan;
            }, limit);
        } catch (DataAccessException e) {
            throw new DatabaseOperationException("Failed to retrieve scan history: " + e.getMessage(), e);
        }
    }

    /**
     * Retrieves all historical scans for a specific URL.
     *
     * @param urlId URL ID
     * @return list of historical scans for this URL
     */
    public List<Scan> findScansByUrlId(Long urlId) {
        String sql = "SELECT scan_id, url_id, scanned_url, scan_score, scan_status, scanned_at " +
                     "FROM scan_history WHERE url_id = ? " +
                     "ORDER BY scanned_at DESC";
        try {
            return jdbcTemplate.query(sql, scanRowMapper, urlId);
        } catch (DataAccessException e) {
            throw new DatabaseOperationException("Failed to retrieve scans for URL ID " + urlId + ": " + e.getMessage(), e);
        }
    }

    // -------------------------------------------------------------------------
    // SCAN_FINDINGS Operations (INSERT, SELECT)
    // -------------------------------------------------------------------------

    /**
     * Inserts individual findings detected during a scan into SCAN_FINDINGS.
     *
     * @param scanId the associated scan_id
     * @param findings list of findings to save
     */
    public void insertFindings(Long scanId, List<Finding> findings) {
        if (findings == null || findings.isEmpty()) {
            return;
        }

        String sql = "INSERT INTO scan_findings (scan_id, rule_name, points, explanation) VALUES (?, ?, ?, ?)";

        try {
            jdbcTemplate.batchUpdate(sql, findings, findings.size(), (ps, finding) -> {
                ps.setLong(1, scanId);
                ps.setString(2, finding.getRuleName());
                ps.setInt(3, finding.getPoints());
                ps.setString(4, finding.getExplanation());
            });
        } catch (DataAccessException e) {
            throw new DatabaseOperationException("Failed to insert scan findings: " + e.getMessage(), e);
        }
    }

    /**
     * Retrieves all findings recorded for a specific scan.
     *
     * @param scanId the scan ID
     * @return list of findings
     */
    public List<Finding> findFindingsByScanId(Long scanId) {
        String sql = "SELECT finding_id, scan_id, rule_name, points, explanation " +
                     "FROM scan_findings WHERE scan_id = ? " +
                     "ORDER BY points DESC";
        try {
            return jdbcTemplate.query(sql, findingRowMapper, scanId);
        } catch (DataAccessException e) {
            throw new DatabaseOperationException("Failed to retrieve findings for scan ID " + scanId + ": " + e.getMessage(), e);
        }
    }

    // -------------------------------------------------------------------------
    // Aggregate & Analytical Queries (COUNT, GROUP BY)
    // -------------------------------------------------------------------------

    /**
     * Demonstrates SQL COUNT to get total scans performed across the system.
     *
     * @return total scan count
     */
    public long countTotalScans() {
        String sql = "SELECT COUNT(*) FROM scan_history";
        try {
            Long count = jdbcTemplate.queryForObject(sql, Long.class);
            return count != null ? count : 0L;
        } catch (DataAccessException e) {
            throw new DatabaseOperationException("Failed to count total scans: " + e.getMessage(), e);
        }
    }

    /**
     * Demonstrates SQL COUNT to get total unique URLs tracked in URL_MASTER.
     *
     * @return unique URL count
     */
    public long countUniqueUrls() {
        String sql = "SELECT COUNT(*) FROM url_master";
        try {
            Long count = jdbcTemplate.queryForObject(sql, Long.class);
            return count != null ? count : 0L;
        } catch (DataAccessException e) {
            throw new DatabaseOperationException("Failed to count unique URLs: " + e.getMessage(), e);
        }
    }

    /**
     * Demonstrates SQL GROUP BY and COUNT to aggregate risk distribution.
     *
     * @return Map of risk status to count (e.g. {"Low Risk": 12, "Suspicious": 5, "High Risk": 3})
     */
    public Map<String, Long> getRiskDistributionStats() {
        String sql = "SELECT scan_status, COUNT(*) AS status_count FROM scan_history GROUP BY scan_status";
        Map<String, Long> stats = new LinkedHashMap<>();
        try {
            jdbcTemplate.query(sql, rs -> {
                stats.put(rs.getString("scan_status"), rs.getLong("status_count"));
            });
            return stats;
        } catch (DataAccessException e) {
            throw new DatabaseOperationException("Failed to aggregate risk distribution statistics: " + e.getMessage(), e);
        }
    }
}
