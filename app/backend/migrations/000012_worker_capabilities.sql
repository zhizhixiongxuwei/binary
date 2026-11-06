CREATE TABLE IF NOT EXISTS worker_capabilities (
    worker_id VARCHAR(160) NOT NULL,
    role VARCHAR(40) NOT NULL,
    report JSON NOT NULL,
    checked_at DATETIME(6) NOT NULL,
    heartbeat_at DATETIME(6) NOT NULL,
    PRIMARY KEY (worker_id),
    KEY idx_worker_capabilities_heartbeat (heartbeat_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
