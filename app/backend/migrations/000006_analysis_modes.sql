-- Uploads are immutable assets. The analysis workflow is chosen only after
-- content detection has completed, so new uploads no longer declare a category.
ALTER TABLE uploads
    MODIFY COLUMN input_category VARCHAR(16) NULL;

-- Historical rows keep input_category. New tasks use analysis_mode so the
-- physical format and the selected workflow are independent concepts.
ALTER TABLE tasks
    ADD COLUMN analysis_mode VARCHAR(16) NULL AFTER input_category,
    ADD CONSTRAINT chk_tasks_analysis_mode
        CHECK (analysis_mode IS NULL OR analysis_mode IN ('binary', 'archive', 'container'));

UPDATE tasks
SET analysis_mode = input_category
WHERE analysis_mode IS NULL
  AND input_category IN ('binary', 'archive', 'container');

-- Only live tasks participate in the one-task-per-upload/mode guarantee.
-- A soft-deleted task therefore does not permanently prevent the user from
-- selecting the same mode again.
ALTER TABLE tasks
    ADD COLUMN active_analysis_mode VARCHAR(16)
        GENERATED ALWAYS AS (IF(deleted_at IS NULL, analysis_mode, NULL)) STORED,
    ADD UNIQUE KEY uq_tasks_upload_analysis_mode (upload_id, active_analysis_mode);
