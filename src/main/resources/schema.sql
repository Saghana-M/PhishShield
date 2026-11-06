-- ---------------------------------------------------------------------
-- Table 1: URL_MASTER
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS url_master (
    url_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    original_url TEXT NOT NULL,
    normalized_url VARCHAR(768) NOT NULL,
    latest_score INT NOT NULL DEFAULT 0,
    latest_status VARCHAR(30) NOT NULL,
    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    total_scans INT NOT NULL DEFAULT 1,
    CONSTRAINT uq_normalized_url UNIQUE (normalized_url)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- Table 2: SCAN_HISTORY
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_history (
    scan_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    url_id BIGINT NOT NULL,
    scanned_url TEXT NOT NULL,
    scan_score INT NOT NULL,
    scan_status VARCHAR(30) NOT NULL,
    scanned_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_scan_history_url
        FOREIGN KEY (url_id) REFERENCES url_master(url_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- Table 3: SCAN_FINDINGS
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_findings (
    finding_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    scan_id BIGINT NOT NULL,
    rule_name VARCHAR(100) NOT NULL,
    points INT NOT NULL,
    explanation TEXT NOT NULL,
    CONSTRAINT fk_scan_findings_scan
        FOREIGN KEY (scan_id) REFERENCES scan_history(scan_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
