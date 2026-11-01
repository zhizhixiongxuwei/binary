-- No task FK: cleanup must survive deletion of the task and service restarts.
CREATE TABLE IF NOT EXISTS task_cleanup_queue (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    kind VARCHAR(16) NOT NULL,
    target VARCHAR(768) NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    target_hash BINARY(32) GENERATED ALWAYS AS (UNHEX(SHA2(target, 256))) STORED,
    UNIQUE KEY uq_task_cleanup_target (kind, target_hash),
    CONSTRAINT chk_task_cleanup_kind CHECK (kind IN ('task', 'path', 'blob'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
