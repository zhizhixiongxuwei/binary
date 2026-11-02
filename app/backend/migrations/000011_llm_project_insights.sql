CREATE TABLE IF NOT EXISTS llm_project_insights (
    source_project_id CHAR(36) NOT NULL,
    cache_key BINARY(32) NOT NULL,
    provider VARCHAR(64) NOT NULL,
    model VARCHAR(200) NOT NULL,
    result_json JSON NOT NULL,
    coverage_json JSON NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (source_project_id, cache_key),
    CONSTRAINT fk_llm_project_insights_project FOREIGN KEY (source_project_id) REFERENCES source_projects (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
