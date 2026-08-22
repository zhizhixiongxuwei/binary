CREATE TABLE IF NOT EXISTS users (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_id CHAR(36) NOT NULL,
    username VARCHAR(128) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(32) NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    must_change_password BOOLEAN NOT NULL DEFAULT TRUE,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY uq_users_public_id (public_id),
    UNIQUE KEY uq_users_username (username),
    CONSTRAINT chk_users_role CHECK (role IN ('reader', 'operator', 'administrator'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS sessions (
    id CHAR(36) NOT NULL,
    user_id BIGINT UNSIGNED NOT NULL,
    token_hash BINARY(32) NOT NULL,
    csrf_token VARCHAR(96) NOT NULL,
    client_ip VARCHAR(64) NULL,
    user_agent VARCHAR(512) NULL,
    expires_at DATETIME(6) NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    last_seen_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY uq_sessions_token_hash (token_hash),
    KEY idx_sessions_user_expiry (user_id, expires_at),
    CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS auth_limits (
    scope_key VARCHAR(255) NOT NULL,
    failure_count INT UNSIGNED NOT NULL DEFAULT 0,
    blocked_until DATETIME(6) NULL,
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (scope_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    actor_user_id BIGINT UNSIGNED NULL,
    action VARCHAR(96) NOT NULL,
    object_type VARCHAR(64) NULL,
    object_id VARCHAR(64) NULL,
    request_id VARCHAR(64) NULL,
    client_ip VARCHAR(64) NULL,
    outcome VARCHAR(32) NOT NULL,
    details JSON NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    KEY idx_audit_actor_time (actor_user_id, created_at),
    KEY idx_audit_object (object_type, object_id, created_at),
    CONSTRAINT fk_audit_actor FOREIGN KEY (actor_user_id) REFERENCES users (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS blobs (
    id CHAR(36) NOT NULL,
    sha256 BINARY(32) NOT NULL,
    size_bytes BIGINT UNSIGNED NOT NULL,
    storage_key VARCHAR(768) NOT NULL,
    state VARCHAR(24) NOT NULL DEFAULT 'ready',
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    deleted_at DATETIME(6) NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_blobs_sha256 (sha256),
    UNIQUE KEY uq_blobs_storage_key (storage_key),
    CONSTRAINT chk_blobs_state CHECK (state IN ('staging', 'ready', 'deleting', 'deleted', 'corrupt'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS uploads (
    id CHAR(36) NOT NULL,
    created_by BIGINT UNSIGNED NOT NULL,
    original_name VARCHAR(512) NOT NULL,
    declared_size BIGINT UNSIGNED NOT NULL,
    received_size BIGINT UNSIGNED NOT NULL DEFAULT 0,
    status VARCHAR(24) NOT NULL DEFAULT 'open',
    blob_id CHAR(36) NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    completed_at DATETIME(6) NULL,
    PRIMARY KEY (id),
    KEY idx_uploads_owner_time (created_by, created_at),
    CONSTRAINT fk_uploads_user FOREIGN KEY (created_by) REFERENCES users (id),
    CONSTRAINT fk_uploads_blob FOREIGN KEY (blob_id) REFERENCES blobs (id),
    CONSTRAINT chk_uploads_status CHECK (status IN ('open', 'complete', 'aborted', 'failed'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS upload_parts (
    upload_id CHAR(36) NOT NULL,
    part_number INT UNSIGNED NOT NULL,
    byte_offset BIGINT UNSIGNED NOT NULL,
    size_bytes BIGINT UNSIGNED NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (upload_id, part_number),
    UNIQUE KEY uq_upload_parts_offset (upload_id, byte_offset),
    CONSTRAINT fk_upload_parts_upload FOREIGN KEY (upload_id) REFERENCES uploads (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS tasks (
    id CHAR(36) NOT NULL,
    created_by BIGINT UNSIGNED NOT NULL,
    blob_id CHAR(36) NOT NULL,
    display_name VARCHAR(512) NOT NULL,
    status VARCHAR(24) NOT NULL DEFAULT 'queued',
    detected_format VARCHAR(64) NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    deleted_at DATETIME(6) NULL,
    PRIMARY KEY (id),
    KEY idx_tasks_owner_time (created_by, created_at),
    KEY idx_tasks_status_time (status, created_at),
    CONSTRAINT fk_tasks_user FOREIGN KEY (created_by) REFERENCES users (id),
    CONSTRAINT fk_tasks_blob FOREIGN KEY (blob_id) REFERENCES blobs (id),
    CONSTRAINT chk_tasks_status CHECK (status IN ('queued', 'scanning', 'ready', 'partial', 'failed', 'deleting', 'deleted'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS task_events (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    task_id CHAR(36) NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    message VARCHAR(1024) NULL,
    progress_current BIGINT NULL,
    progress_total BIGINT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    KEY idx_task_events_task_id (task_id, id),
    CONSTRAINT fk_task_events_task FOREIGN KEY (task_id) REFERENCES tasks (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS file_nodes (
    id CHAR(36) NOT NULL,
    task_id CHAR(36) NOT NULL,
    parent_id CHAR(36) NULL,
    blob_id CHAR(36) NULL,
    logical_path VARCHAR(1024) NOT NULL,
    node_kind VARCHAR(24) NOT NULL,
    detected_format VARCHAR(64) NULL,
    size_bytes BIGINT UNSIGNED NOT NULL DEFAULT 0,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    KEY idx_file_nodes_task_parent (task_id, parent_id, id),
    KEY idx_file_nodes_task_format (task_id, detected_format, id),
    CONSTRAINT fk_file_nodes_task FOREIGN KEY (task_id) REFERENCES tasks (id) ON DELETE CASCADE,
    CONSTRAINT fk_file_nodes_parent FOREIGN KEY (parent_id) REFERENCES file_nodes (id) ON DELETE CASCADE,
    CONSTRAINT fk_file_nodes_blob FOREIGN KEY (blob_id) REFERENCES blobs (id),
    CONSTRAINT chk_file_nodes_kind CHECK (node_kind IN ('file', 'directory', 'image', 'archive', 'virtual'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS runs (
    id CHAR(36) NOT NULL,
    kind VARCHAR(40) NOT NULL,
    status VARCHAR(24) NOT NULL DEFAULT 'queued',
    task_id CHAR(36) NULL,
    subject_type VARCHAR(32) NOT NULL,
    subject_id CHAR(36) NOT NULL,
    created_by BIGINT UNSIGNED NULL,
    idempotency_key VARCHAR(128) NOT NULL,
    request JSON NULL,
    result_quality VARCHAR(32) NULL,
    tool_name VARCHAR(64) NULL,
    tool_version VARCHAR(128) NULL,
    image_reference VARCHAR(255) NULL,
    ruleset_version VARCHAR(128) NULL,
    error_code VARCHAR(64) NULL,
    error_message VARCHAR(1024) NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    started_at DATETIME(6) NULL,
    completed_at DATETIME(6) NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_runs_idempotency (created_by, kind, subject_id, idempotency_key),
    KEY idx_runs_task_kind_time (task_id, kind, created_at),
    CONSTRAINT fk_runs_task FOREIGN KEY (task_id) REFERENCES tasks (id) ON DELETE CASCADE,
    CONSTRAINT fk_runs_user FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT chk_runs_status CHECK (status IN ('queued', 'running', 'complete', 'partial', 'unsupported', 'failed', 'cancelled')),
    CONSTRAINT chk_runs_kind CHECK (kind IN ('scan', 'archive_import', 'trivy_scan', 'native_decompile', 'jvm_decompile', 'pyc_decompile', 'c_check', 'java_check', 'python_check'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS jobs (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    run_id CHAR(36) NOT NULL,
    kind VARCHAR(40) NOT NULL,
    status VARCHAR(24) NOT NULL DEFAULT 'queued',
    priority INT NOT NULL DEFAULT 0,
    available_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    claim_count INT UNSIGNED NOT NULL DEFAULT 0,
    attempt_count INT UNSIGNED NOT NULL DEFAULT 0,
    max_attempts INT UNSIGNED NOT NULL DEFAULT 3,
    fencing_token BIGINT UNSIGNED NOT NULL DEFAULT 0,
    lease_owner VARCHAR(128) NULL,
    lease_until DATETIME(6) NULL,
    heartbeat_at DATETIME(6) NULL,
    cancel_requested_at DATETIME(6) NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY uq_jobs_run (run_id),
    KEY idx_jobs_claim (kind, status, priority, available_at, id),
    KEY idx_jobs_expired (status, lease_until, id),
    CONSTRAINT fk_jobs_run FOREIGN KEY (run_id) REFERENCES runs (id) ON DELETE CASCADE,
    CONSTRAINT chk_jobs_status CHECK (status IN ('queued', 'leased', 'running', 'succeeded', 'failed', 'cancelled'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS job_attempts (
    job_id BIGINT UNSIGNED NOT NULL,
    attempt_number INT UNSIGNED NOT NULL,
    worker_id VARCHAR(128) NOT NULL,
    fencing_token BIGINT UNSIGNED NOT NULL,
    status VARCHAR(24) NOT NULL DEFAULT 'running',
    error_code VARCHAR(64) NULL,
    error_message VARCHAR(1024) NULL,
    started_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    completed_at DATETIME(6) NULL,
    PRIMARY KEY (job_id, attempt_number),
    KEY idx_job_attempts_worker (worker_id, started_at),
    CONSTRAINT fk_job_attempts_job FOREIGN KEY (job_id) REFERENCES jobs (id) ON DELETE CASCADE,
    CONSTRAINT chk_job_attempts_status CHECK (status IN ('running', 'succeeded', 'failed', 'cancelled', 'lease_lost'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS resource_slots (
    pool VARCHAR(40) NOT NULL,
    slot_number INT UNSIGNED NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    job_id BIGINT UNSIGNED NULL,
    fencing_token BIGINT UNSIGNED NULL,
    lease_owner VARCHAR(128) NULL,
    acquired_at DATETIME(6) NULL,
    PRIMARY KEY (pool, slot_number),
    KEY idx_resource_slots_available (pool, enabled, job_id, slot_number),
    CONSTRAINT fk_resource_slots_job FOREIGN KEY (job_id) REFERENCES jobs (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS source_projects (
    id CHAR(36) NOT NULL,
    task_id CHAR(36) NOT NULL,
    file_node_id CHAR(36) NOT NULL,
    run_id CHAR(36) NOT NULL,
    source_kind VARCHAR(24) NOT NULL,
    language VARCHAR(24) NOT NULL,
    result_quality VARCHAR(32) NOT NULL,
    root_storage_key VARCHAR(768) NOT NULL,
    file_count INT UNSIGNED NOT NULL DEFAULT 0,
    symbol_count INT UNSIGNED NOT NULL DEFAULT 0,
    size_bytes BIGINT UNSIGNED NOT NULL DEFAULT 0,
    state VARCHAR(24) NOT NULL DEFAULT 'ready',
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    deleted_at DATETIME(6) NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_source_projects_run (run_id),
    UNIQUE KEY uq_source_projects_storage (root_storage_key),
    KEY idx_source_projects_task_time (task_id, created_at),
    CONSTRAINT fk_source_projects_task FOREIGN KEY (task_id) REFERENCES tasks (id) ON DELETE CASCADE,
    CONSTRAINT fk_source_projects_file FOREIGN KEY (file_node_id) REFERENCES file_nodes (id),
    CONSTRAINT fk_source_projects_run FOREIGN KEY (run_id) REFERENCES runs (id) ON DELETE CASCADE,
    CONSTRAINT chk_source_projects_kind CHECK (source_kind IN ('native', 'jvm', 'pyc')),
    CONSTRAINT chk_source_projects_language CHECK (language IN ('c', 'java', 'python')),
    CONSTRAINT chk_source_projects_quality CHECK (result_quality IN ('source', 'partial_source', 'bytecode_only')),
    CONSTRAINT chk_source_projects_state CHECK (state IN ('ready', 'deleting', 'deleted', 'corrupt'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS findings (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    task_id CHAR(36) NOT NULL,
    run_id CHAR(36) NOT NULL,
    finding_type VARCHAR(32) NOT NULL,
    language VARCHAR(24) NULL,
    severity VARCHAR(16) NOT NULL,
    rule_id VARCHAR(128) NULL,
    cwe VARCHAR(32) NULL,
    external_id VARCHAR(128) NULL,
    logical_path VARCHAR(1024) NULL,
    start_line INT UNSIGNED NULL,
    start_column INT UNSIGNED NULL,
    end_line INT UNSIGNED NULL,
    end_column INT UNSIGNED NULL,
    title VARCHAR(512) NOT NULL,
    message TEXT NOT NULL,
    snippet TEXT NULL,
    details JSON NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    KEY idx_findings_run_id (run_id, id),
    KEY idx_findings_task_severity (task_id, severity, id),
    KEY idx_findings_task_rule (task_id, rule_id, id),
    KEY idx_findings_external (external_id, task_id),
    CONSTRAINT fk_findings_task FOREIGN KEY (task_id) REFERENCES tasks (id) ON DELETE CASCADE,
    CONSTRAINT fk_findings_run FOREIGN KEY (run_id) REFERENCES runs (id) ON DELETE CASCADE,
    CONSTRAINT chk_findings_type CHECK (finding_type IN ('code', 'vulnerability')),
    CONSTRAINT chk_findings_language CHECK (language IS NULL OR language IN ('c', 'java', 'python')),
    CONSTRAINT chk_findings_severity CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS run_artifacts (
    id CHAR(36) NOT NULL,
    task_id CHAR(36) NOT NULL,
    run_id CHAR(36) NOT NULL,
    artifact_kind VARCHAR(64) NOT NULL,
    media_type VARCHAR(128) NOT NULL,
    storage_key VARCHAR(768) NOT NULL,
    size_bytes BIGINT UNSIGNED NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY uq_run_artifacts_run_kind (run_id, artifact_kind),
    UNIQUE KEY uq_run_artifacts_storage (storage_key),
    KEY idx_run_artifacts_task_time (task_id, created_at),
    CONSTRAINT fk_run_artifacts_task FOREIGN KEY (task_id) REFERENCES tasks (id) ON DELETE CASCADE,
    CONSTRAINT fk_run_artifacts_run FOREIGN KEY (run_id) REFERENCES runs (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS archive_entries (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    import_run_id CHAR(36) NOT NULL,
    ordinal INT UNSIGNED NOT NULL,
    logical_path VARCHAR(1024) NOT NULL,
    size_bytes BIGINT UNSIGNED NOT NULL,
    detected_format VARCHAR(64) NULL,
    status VARCHAR(24) NOT NULL,
    blob_id CHAR(36) NULL,
    created_task_id CHAR(36) NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY uq_archive_entries_ordinal (import_run_id, ordinal),
    UNIQUE KEY uq_archive_entries_task (created_task_id),
    CONSTRAINT fk_archive_entries_run FOREIGN KEY (import_run_id) REFERENCES runs (id) ON DELETE CASCADE,
    CONSTRAINT fk_archive_entries_blob FOREIGN KEY (blob_id) REFERENCES blobs (id),
    CONSTRAINT fk_archive_entries_task FOREIGN KEY (created_task_id) REFERENCES tasks (id),
    CONSTRAINT chk_archive_entries_status CHECK (status IN ('candidate', 'skipped', 'materialized', 'task_created', 'failed'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS reports (
    id CHAR(36) NOT NULL,
    task_id CHAR(36) NOT NULL,
    created_by BIGINT UNSIGNED NOT NULL,
    format VARCHAR(16) NOT NULL,
    status VARCHAR(24) NOT NULL DEFAULT 'ready',
    storage_key VARCHAR(768) NOT NULL,
    selected_run_ids JSON NOT NULL,
    snapshot JSON NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    deleted_at DATETIME(6) NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_reports_storage (storage_key),
    KEY idx_reports_task_time (task_id, created_at),
    CONSTRAINT fk_reports_task FOREIGN KEY (task_id) REFERENCES tasks (id) ON DELETE CASCADE,
    CONSTRAINT fk_reports_user FOREIGN KEY (created_by) REFERENCES users (id),
    CONSTRAINT chk_reports_format CHECK (format IN ('json', 'html', 'docx')),
    CONSTRAINT chk_reports_status CHECK (status IN ('ready', 'deleting', 'deleted', 'failed'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
