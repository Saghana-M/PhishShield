-- =====================================================================
-- PhishShield – Phishing URL Risk Detection System
-- Database Schema Script for MySQL 8
-- Database Name: phishshield_db
-- =====================================================================

CREATE DATABASE IF NOT EXISTS phishshield_db
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE phishshield_db;

-- ---------------------------------------------------------------------
-- Table 1: URL_MASTER
-- Purpose: Stores each unique URL, maintaining cumulative scan statistics
--          and the most recent risk status.
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
-- Purpose: Stores every individual scan event, including repeated
--          submissions over time.
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

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_scan_history_url_id ON scan_history(url_id);
CREATE INDEX IF NOT EXISTS idx_scan_history_scanned_at ON scan_history(scanned_at DESC);

-- ---------------------------------------------------------------------
-- Table 3: SCAN_FINDINGS
-- Purpose: Stores the specific warning signs (detection rule triggers)
--          identified during each scan.
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

-- Index on scan_id for fast retrieval of findings for any scan
CREATE INDEX IF NOT EXISTS idx_scan_findings_scan_id ON scan_findings(scan_id);
