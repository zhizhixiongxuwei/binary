CREATE TABLE IF NOT EXISTS component_inventories (
 id CHAR(36) PRIMARY KEY, task_id CHAR(36) NOT NULL, run_id CHAR(36) NOT NULL,
 input_sha256 CHAR(64) NOT NULL, fingerprint CHAR(64) NOT NULL, source VARCHAR(32) NOT NULL,
 quality VARCHAR(24) NOT NULL, document JSON NOT NULL, created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
 UNIQUE KEY uq_inventory_run(run_id), KEY idx_inventory_task(task_id,created_at),
 FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE,
 FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
CREATE TABLE IF NOT EXISTS sbom_documents (
 id CHAR(36) PRIMARY KEY, task_id CHAR(36) NOT NULL, run_id CHAR(36) NOT NULL,
 standard VARCHAR(24) NOT NULL, spec_version VARCHAR(32) NOT NULL, encoding VARCHAR(16) NOT NULL,
 input_sha256 CHAR(64) NOT NULL, parser_version VARCHAR(64) NOT NULL, diagnostics JSON NOT NULL,
 created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6), UNIQUE KEY uq_sbom_run(run_id),
 FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE, FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
CREATE TABLE IF NOT EXISTS component_instances (
 id CHAR(64) NOT NULL, inventory_id CHAR(36) NOT NULL, identity_key CHAR(64) NOT NULL,
 name VARCHAR(512) NOT NULL, version VARCHAR(255) NOT NULL, purl TEXT NULL, logical_path TEXT NOT NULL, details JSON NOT NULL,
 PRIMARY KEY(inventory_id,id), KEY idx_component_identity(identity_key),
 FOREIGN KEY(inventory_id) REFERENCES component_inventories(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
CREATE TABLE IF NOT EXISTS component_dependencies (
 inventory_id CHAR(36) NOT NULL, relation_key CHAR(64) NOT NULL, details JSON NOT NULL,
 PRIMARY KEY(inventory_id,relation_key), FOREIGN KEY(inventory_id) REFERENCES component_inventories(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
CREATE TABLE IF NOT EXISTS sca_sbom_links (
 task_id CHAR(36) NOT NULL, sbom_task_id CHAR(36) NOT NULL, verification JSON NOT NULL,
 created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6), PRIMARY KEY(task_id,sbom_task_id),
 FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE, FOREIGN KEY(sbom_task_id) REFERENCES tasks(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
