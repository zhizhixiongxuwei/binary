CREATE TABLE IF NOT EXISTS environment_profiles (
 id CHAR(36) PRIMARY KEY, name VARCHAR(255) NOT NULL, created_by BIGINT UNSIGNED NOT NULL,
 revision BIGINT UNSIGNED NOT NULL DEFAULT 1, created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
CREATE TABLE IF NOT EXISTS environment_versions (
 id CHAR(36) PRIMARY KEY, profile_id CHAR(36) NOT NULL, revision BIGINT UNSIGNED NOT NULL,
 fingerprint CHAR(64) NOT NULL, config JSON NOT NULL, created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
 UNIQUE KEY uq_environment_version(profile_id,revision), FOREIGN KEY(profile_id) REFERENCES environment_profiles(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
CREATE TABLE IF NOT EXISTS analysis_policy_versions (
 id CHAR(36) PRIMARY KEY, task_id CHAR(36) NOT NULL, config JSON NOT NULL, fingerprint CHAR(64) NOT NULL,
 created_by BIGINT UNSIGNED NOT NULL, created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
 KEY idx_policy_task(task_id,created_at), FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
CREATE TABLE IF NOT EXISTS vulnerability_occurrences (
 id CHAR(64) PRIMARY KEY, task_id CHAR(36) NOT NULL, input_sha256 CHAR(64) NOT NULL,
 component_id CHAR(64) NOT NULL, vulnerability_id VARCHAR(128) NOT NULL, severity VARCHAR(16) NOT NULL,
 details JSON NOT NULL, created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
 KEY idx_occurrence_task(task_id,severity,id), FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
CREATE TABLE IF NOT EXISTS occurrence_findings (
 occurrence_id CHAR(64) NOT NULL, finding_id BIGINT UNSIGNED NOT NULL, inventory_id CHAR(36) NOT NULL,
 PRIMARY KEY(occurrence_id,finding_id), FOREIGN KEY(occurrence_id) REFERENCES vulnerability_occurrences(id) ON DELETE CASCADE,
 FOREIGN KEY(finding_id) REFERENCES findings(id) ON DELETE CASCADE,
 FOREIGN KEY(inventory_id) REFERENCES component_inventories(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
CREATE TABLE IF NOT EXISTS vulnerability_assessments (
 id CHAR(64) PRIMARY KEY, occurrence_id CHAR(64) NOT NULL, run_id CHAR(36) NOT NULL, environment_version_id CHAR(36) NOT NULL,
 policy_id CHAR(36) NOT NULL, knowledge_digest CHAR(64) NOT NULL, reachability VARCHAR(24) NOT NULL,
 environment_applicability VARCHAR(24) NOT NULL, attack_preconditions VARCHAR(24) NOT NULL,
 details JSON NOT NULL, created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
 UNIQUE KEY uq_assessment_run(occurrence_id,run_id), KEY idx_assessment_scope(occurrence_id,environment_version_id,created_at),
 FOREIGN KEY(occurrence_id) REFERENCES vulnerability_occurrences(id) ON DELETE CASCADE,
 FOREIGN KEY(run_id) REFERENCES runs(id) ON DELETE CASCADE,
 FOREIGN KEY(environment_version_id) REFERENCES environment_versions(id), FOREIGN KEY(policy_id) REFERENCES analysis_policy_versions(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
CREATE TABLE IF NOT EXISTS vulnerability_dispositions (
 occurrence_id CHAR(64) NOT NULL, environment_profile_id CHAR(36) NOT NULL, environment_version_id CHAR(36) NOT NULL,
 status VARCHAR(16) NOT NULL DEFAULT 'open', source VARCHAR(16) NOT NULL DEFAULT 'policy', revision BIGINT UNSIGNED NOT NULL DEFAULT 0,
 assessment_id CHAR(64) NULL, reason VARCHAR(1024) NOT NULL DEFAULT '', override_until DATETIME(6) NULL,
 expires_at DATETIME(6) NULL, updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
 PRIMARY KEY(occurrence_id,environment_profile_id), CHECK(status IN ('open','ignored')), CHECK(source IN ('manual','policy')),
 FOREIGN KEY(occurrence_id) REFERENCES vulnerability_occurrences(id) ON DELETE CASCADE,
 FOREIGN KEY(environment_profile_id) REFERENCES environment_profiles(id), FOREIGN KEY(environment_version_id) REFERENCES environment_versions(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
CREATE TABLE IF NOT EXISTS disposition_events (
 id CHAR(36) PRIMARY KEY, occurrence_id CHAR(64) NOT NULL, environment_profile_id CHAR(36) NOT NULL,
 revision BIGINT UNSIGNED NOT NULL, event_key VARCHAR(128) NOT NULL, actor_id BIGINT UNSIGNED NULL,
 details JSON NOT NULL, created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
 UNIQUE KEY uq_disposition_event(occurrence_id,environment_profile_id,event_key),
 KEY idx_disposition_history(occurrence_id,created_at), FOREIGN KEY(occurrence_id) REFERENCES vulnerability_occurrences(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
