-- Log Threat Analyzer - database schema (see docs/DESIGN.md, section 4)
-- All DATETIME values are stored in UTC.
-- Safe to run more than once: tables are created only if they do not exist.

CREATE TABLE IF NOT EXISTS analysis_runs (
    id                    INT AUTO_INCREMENT PRIMARY KEY,
    filename              VARCHAR(255) NOT NULL,
    file_hash             CHAR(64)     NOT NULL,
    created_at            DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status                ENUM('pending', 'completed', 'failed') NOT NULL DEFAULT 'pending',
    error_message         VARCHAR(500) NULL,
    lines_parsed          INT          NULL,
    time_window_seconds   INT NOT NULL,
    brute_force_threshold INT NOT NULL,
    scanning_threshold    INT NOT NULL,
    INDEX idx_runs_file_hash (file_hash),
    INDEX idx_runs_created_at (created_at)
);

CREATE TABLE IF NOT EXISTS alerts (
    id               INT AUTO_INCREMENT PRIMARY KEY,
    analysis_run_id  INT          NOT NULL,
    threat_type      VARCHAR(50)  NOT NULL,
    ip_address       VARCHAR(45)  NOT NULL,
    detected_at      DATETIME     NOT NULL,
    details          VARCHAR(255) NOT NULL,
    CONSTRAINT fk_alerts_run
        FOREIGN KEY (analysis_run_id) REFERENCES analysis_runs(id)
        ON DELETE CASCADE,
    INDEX idx_alerts_run_type (analysis_run_id, threat_type)
);
