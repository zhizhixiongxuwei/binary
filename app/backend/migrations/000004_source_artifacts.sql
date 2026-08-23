ALTER TABLE source_projects
    ADD COLUMN input_blob_id CHAR(36) NULL AFTER file_node_id,
    ADD COLUMN manifest_sha256 BINARY(32) NULL AFTER root_storage_key,
    ADD CONSTRAINT fk_source_projects_input_blob
        FOREIGN KEY (input_blob_id) REFERENCES blobs (id);

CREATE TABLE IF NOT EXISTS source_files (
    id CHAR(36) NOT NULL,
    source_project_id CHAR(36) NOT NULL,
    logical_path VARCHAR(1024) NOT NULL,
    logical_path_sha256 BINARY(32)
        GENERATED ALWAYS AS (UNHEX(SHA2(CAST(logical_path AS BINARY), 256))) STORED,
    language VARCHAR(24) NOT NULL,
    media_type VARCHAR(128) NOT NULL DEFAULT 'text/plain; charset=utf-8',
    sha256 BINARY(32) NOT NULL,
    size_bytes BIGINT UNSIGNED NOT NULL,
    line_count INT UNSIGNED NOT NULL,
    state VARCHAR(24) NOT NULL DEFAULT 'ready',
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    deleted_at DATETIME(6) NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_source_files_project_path (source_project_id, logical_path_sha256),
    KEY idx_source_files_project_id (source_project_id, id),
    CONSTRAINT fk_source_files_project
        FOREIGN KEY (source_project_id) REFERENCES source_projects (id) ON DELETE CASCADE,
    CONSTRAINT chk_source_files_language CHECK (language IN ('c', 'java', 'python')),
    CONSTRAINT chk_source_files_state CHECK (state IN ('ready', 'deleting', 'deleted', 'corrupt'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS source_symbols (
    id CHAR(36) NOT NULL,
    source_project_id CHAR(36) NOT NULL,
    source_file_id CHAR(36) NOT NULL,
    symbol_kind VARCHAR(32) NOT NULL,
    name VARCHAR(512) NOT NULL,
    signature VARCHAR(2048) NULL,
    start_line INT UNSIGNED NOT NULL,
    start_column INT UNSIGNED NOT NULL DEFAULT 1,
    end_line INT UNSIGNED NOT NULL,
    end_column INT UNSIGNED NOT NULL DEFAULT 1,
    origin_locator JSON NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    KEY idx_source_symbols_project_file (source_project_id, source_file_id, id),
    CONSTRAINT fk_source_symbols_project
        FOREIGN KEY (source_project_id) REFERENCES source_projects (id) ON DELETE CASCADE,
    CONSTRAINT fk_source_symbols_file
        FOREIGN KEY (source_file_id) REFERENCES source_files (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

ALTER TABLE findings
    ADD COLUMN source_project_id CHAR(36) NULL AFTER run_id,
    ADD COLUMN source_file_id CHAR(36) NULL AFTER source_project_id,
    ADD COLUMN snippet_start_line INT UNSIGNED NULL AFTER snippet,
    ADD KEY idx_findings_source_file (source_file_id, id),
    ADD CONSTRAINT fk_findings_source_project
        FOREIGN KEY (source_project_id) REFERENCES source_projects (id),
    ADD CONSTRAINT fk_findings_source_file
        FOREIGN KEY (source_file_id) REFERENCES source_files (id);

ALTER TABLE run_artifacts
    ADD COLUMN sha256 BINARY(32) NULL AFTER size_bytes,
    ADD COLUMN schema_version VARCHAR(64) NULL AFTER sha256,
    ADD COLUMN state VARCHAR(24) NOT NULL DEFAULT 'ready' AFTER schema_version,
    ADD COLUMN metadata JSON NULL AFTER state,
    ADD COLUMN deleted_at DATETIME(6) NULL AFTER created_at,
    ADD CONSTRAINT chk_run_artifacts_state
        CHECK (state IN ('staging', 'ready', 'deleting', 'deleted', 'corrupt'));

ALTER TABLE reports
    ADD COLUMN schema_version VARCHAR(64) NOT NULL DEFAULT 'binaryscan-report-v1' AFTER format,
    ADD COLUMN sha256 BINARY(32) NULL AFTER storage_key,
    ADD COLUMN size_bytes BIGINT UNSIGNED NULL AFTER sha256;
