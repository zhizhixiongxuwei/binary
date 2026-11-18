SET @impact_generation_ddl = IF(
 (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='vulnerability_dispositions' AND column_name='pending_run_id')=0,
 'ALTER TABLE vulnerability_dispositions ADD COLUMN pending_run_id CHAR(36) NULL', 'SELECT 1');
PREPARE impact_generation_stmt FROM @impact_generation_ddl;
EXECUTE impact_generation_stmt;
DEALLOCATE PREPARE impact_generation_stmt;
