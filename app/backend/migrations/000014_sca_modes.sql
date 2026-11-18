-- Each ALTER atomically replaces the same constraint: safe to repeat after a
-- later statement fails (MySQL DDL commits independently of migration records).
ALTER TABLE uploads DROP CHECK chk_uploads_input_category, DROP CHECK chk_uploads_detected_category,
 ADD CONSTRAINT chk_uploads_input_category CHECK (input_category IS NULL OR input_category IN ('binary','archive','container','sbom')),
 ADD CONSTRAINT chk_uploads_detected_category CHECK (detected_category IS NULL OR detected_category IN ('binary','archive','container','sbom'));
ALTER TABLE tasks DROP CHECK chk_tasks_input_category, DROP CHECK chk_tasks_detected_category, DROP CHECK chk_tasks_analysis_mode,
 ADD CONSTRAINT chk_tasks_input_category CHECK (input_category IS NULL OR input_category IN ('binary','archive','container','sbom')),
 ADD CONSTRAINT chk_tasks_detected_category CHECK (detected_category IS NULL OR detected_category IN ('binary','archive','container','sbom')),
 ADD CONSTRAINT chk_tasks_analysis_mode CHECK (analysis_mode IS NULL OR analysis_mode IN ('binary','archive','container','sbom','java_sca'));
ALTER TABLE runs DROP CHECK chk_runs_kind,
 ADD CONSTRAINT chk_runs_kind CHECK (kind IN ('scan','archive_import','trivy_scan','native_decompile','jvm_decompile','pyc_decompile','c_check','java_check','python_check','sbom_parse','sca_scan','impact_analysis'));
