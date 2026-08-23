ALTER TABLE reports
    ADD COLUMN idempotency_key VARCHAR(128) NULL AFTER created_by;

UPDATE reports
SET idempotency_key = CONCAT('legacy:', id)
WHERE idempotency_key IS NULL;

ALTER TABLE reports
    MODIFY COLUMN idempotency_key VARCHAR(128) NOT NULL,
    ADD UNIQUE KEY uq_reports_owner_task_idempotency
        (created_by, task_id, idempotency_key);
