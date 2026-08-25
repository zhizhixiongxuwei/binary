CREATE TABLE IF NOT EXISTS archive_report_bundles (
    id CHAR(36) NOT NULL,
    import_run_id CHAR(36) NOT NULL,
    created_by BIGINT UNSIGNED NOT NULL,
    idempotency_key VARCHAR(128) NOT NULL,
    status VARCHAR(24) NOT NULL DEFAULT 'ready',
    schema_version VARCHAR(64) NOT NULL DEFAULT 'binaryscan-archive-report-bundle-v1',
    storage_key VARCHAR(768) NOT NULL,
    sha256 BINARY(32) NOT NULL,
    size_bytes BIGINT UNSIGNED NOT NULL,
    options JSON NOT NULL,
    manifest JSON NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    deleted_at DATETIME(6) NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_archive_report_bundles_storage (storage_key),
    UNIQUE KEY uq_archive_report_bundles_intent
        (created_by, import_run_id, idempotency_key),
    KEY idx_archive_report_bundles_import_time (import_run_id, created_at),
    CONSTRAINT fk_archive_report_bundles_run
        FOREIGN KEY (import_run_id) REFERENCES runs (id) ON DELETE CASCADE,
    CONSTRAINT fk_archive_report_bundles_user
        FOREIGN KEY (created_by) REFERENCES users (id),
    CONSTRAINT chk_archive_report_bundles_status
        CHECK (status IN ('ready', 'deleting', 'deleted', 'failed'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
