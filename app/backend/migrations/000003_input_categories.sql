ALTER TABLE uploads
    ADD COLUMN input_category VARCHAR(16) NULL AFTER original_name,
    ADD COLUMN content_type VARCHAR(255) NULL AFTER input_category,
    ADD COLUMN idempotency_key VARCHAR(128) NULL AFTER content_type,
    ADD COLUMN validation_status VARCHAR(24) NULL AFTER status,
    ADD COLUMN detected_category VARCHAR(16) NULL AFTER validation_status,
    ADD COLUMN detected_format VARCHAR(64) NULL AFTER detected_category,
    ADD COLUMN validation_error JSON NULL AFTER detected_format,
    ADD COLUMN expires_at DATETIME(6) NULL AFTER completed_at,
    ADD COLUMN assembly_started_at DATETIME(6) NULL AFTER expires_at,
    ADD COLUMN assembly_token CHAR(36) NULL AFTER assembly_started_at,
    ADD UNIQUE KEY uq_uploads_owner_idempotency (created_by, idempotency_key),
    ADD CONSTRAINT chk_uploads_input_category
        CHECK (input_category IS NULL OR input_category IN ('binary', 'archive', 'container')),
    ADD CONSTRAINT chk_uploads_validation_status
        CHECK (validation_status IS NULL OR validation_status IN ('pending', 'valid', 'mismatch', 'unsupported')),
    ADD CONSTRAINT chk_uploads_detected_category
        CHECK (detected_category IS NULL OR detected_category IN ('binary', 'archive', 'container'));

ALTER TABLE upload_parts
    ADD COLUMN sha256 BINARY(32) NULL AFTER size_bytes;

ALTER TABLE tasks
    ADD COLUMN upload_id CHAR(36) NULL AFTER created_by,
    ADD COLUMN input_category VARCHAR(16) NULL AFTER display_name,
    ADD COLUMN detected_category VARCHAR(16) NULL AFTER input_category,
    ADD KEY idx_tasks_upload_id (upload_id),
    ADD CONSTRAINT fk_tasks_upload FOREIGN KEY (upload_id) REFERENCES uploads (id),
    ADD CONSTRAINT chk_tasks_input_category
        CHECK (input_category IS NULL OR input_category IN ('binary', 'archive', 'container')),
    ADD CONSTRAINT chk_tasks_detected_category
        CHECK (detected_category IS NULL OR detected_category IN ('binary', 'archive', 'container'));

UPDATE tasks
SET detected_category = CASE
        WHEN detected_format IN ('pe', 'pe32', 'pe32+', 'elf', 'elf32', 'elf64', 'mach-o', 'macho', 'macho-thin', 'macho-fat',
                                 'class', 'java-class', 'jar', 'war', 'ear', 'dex', 'apk', 'pyc') THEN 'binary'
        WHEN detected_format IN ('zip', '7z', 'rar', 'tar', 'gzip', 'xz', 'deb', 'rpm') THEN 'archive'
        WHEN detected_format IN ('docker-tar', 'oci-tar') THEN 'container'
        ELSE NULL
    END
WHERE detected_category IS NULL;

-- Existing installations can contain uploads created before categorized
-- intake existed. Pick the newest live task sharing the same content blob as
-- the best available detector evidence, while retaining a safe binary default
-- when no task can be linked.
UPDATE uploads u
LEFT JOIN tasks linked
    ON linked.blob_id = u.blob_id AND linked.deleted_at IS NULL
LEFT JOIN tasks newer
    ON newer.blob_id = linked.blob_id AND newer.deleted_at IS NULL
   AND (newer.created_at > linked.created_at
        OR (newer.created_at = linked.created_at AND newer.id > linked.id))
SET u.content_type = COALESCE(NULLIF(u.content_type, ''), 'application/octet-stream'),
    u.input_category = COALESCE(linked.detected_category, 'binary'),
    u.validation_status = CASE WHEN u.status = 'complete' THEN 'valid' ELSE 'pending' END,
    u.detected_category = CASE
        WHEN u.status = 'complete' THEN COALESCE(linked.detected_category, 'binary')
        ELSE u.detected_category
    END,
    u.detected_format = CASE
        WHEN u.status = 'complete' THEN COALESCE(NULLIF(linked.detected_format, ''), 'unknown')
        ELSE u.detected_format
    END,
    u.expires_at = COALESCE(u.expires_at, DATE_ADD(u.created_at, INTERVAL 1 DAY))
WHERE newer.id IS NULL;

ALTER TABLE uploads
    MODIFY COLUMN input_category VARCHAR(16) NOT NULL,
    MODIFY COLUMN content_type VARCHAR(255) NOT NULL,
    MODIFY COLUMN validation_status VARCHAR(24) NOT NULL,
    MODIFY COLUMN expires_at DATETIME(6) NOT NULL;
