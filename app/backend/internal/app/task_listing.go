package app

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type taskArchiveSummary struct {
	ImportID       string `json:"import_id"`
	UploadID       string `json:"upload_id"`
	Status         string `json:"status"`
	SourceRetained bool   `json:"source_retained"`
	ChildCount     int    `json:"child_count"`
	CompletedCount int    `json:"completed_count"`
	ActiveCount    int    `json:"active_count"`
	FailedCount    int    `json:"failed_count"`
}

// A removed archive source remains a group while any child or report bundle
// survives. Its task ID remains stable across imports and source removal.
const taskRootVisibility = `(t.deleted_at IS NULL OR
	EXISTS (SELECT 1 FROM runs retained_run JOIN archive_entries retained_entry ON retained_entry.import_run_id = retained_run.id
	 JOIN tasks retained_child ON retained_child.id = retained_entry.created_task_id AND retained_child.deleted_at IS NULL
	 WHERE retained_run.task_id = t.id AND retained_run.kind = 'archive_import') OR
	EXISTS (SELECT 1 FROM runs retained_run JOIN archive_report_bundles retained_bundle ON retained_bundle.import_run_id = retained_run.id
	 WHERE retained_run.task_id = t.id AND retained_run.kind = 'archive_import' AND retained_bundle.status = 'ready' AND retained_bundle.deleted_at IS NULL))
	AND NOT EXISTS (SELECT 1 FROM archive_entries derived WHERE derived.created_task_id = t.id)`

func (s *taskService) listTaskChildren(c *gin.Context) {
	s.listTaskPage(c, c.Param("taskID"))
}

// Record filters are tested together against a single parent/child so a keyword
// hit in one child and a status hit in a different child cannot fabricate a hit.
func taskRecordFilters(options taskListOptions, alias, archivePath string) ([]string, []any) {
	conditions := make([]string, 0, 4)
	args := make([]any, 0, 5)
	if options.Keyword != "" {
		pattern := "%" + options.Keyword + "%"
		condition := "(" + alias + ".display_name LIKE ? OR " + alias + ".id LIKE ?"
		args = append(args, pattern, pattern)
		if archivePath != "" {
			condition += " OR " + archivePath + " LIKE ?"
			args = append(args, pattern)
		}
		conditions = append(conditions, condition+")")
	}
	if options.Status != "" {
		conditions = append(conditions, alias+".status = ?")
		args = append(args, options.Status)
	}
	if options.ExecutionStatus != "" {
		conditions = append(conditions, "("+taskExecutionStatusSQL(alias)+") = ?")
		args = append(args, options.ExecutionStatus)
	}
	if options.InputType != "" {
		conditions = append(conditions, "LOWER(COALESCE(NULLIF("+alias+".detected_format, ''), 'unknown')) = ?")
		args = append(args, options.InputType)
	}
	if options.Tag != "" {
		conditions = append(conditions, "LOWER(COALESCE("+alias+".detected_format, '')) = ?")
		args = append(args, strings.ToLower(options.Tag))
	}
	return conditions, args
}

func (s *taskService) listTaskPage(c *gin.Context, parentID string) {
	options, err := parseTaskListOptions(c.Request.URL.Query())
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_task_list_query"})
		return
	}
	conditions := []string{taskRootVisibility}
	args := make([]any, 0, 24)
	joins, archivePath := "", "''"
	if parentID != "" {
		var exists int
		if err := s.db.QueryRowContext(c, `SELECT COUNT(*) FROM tasks t WHERE t.id = ? AND (`+taskRootVisibility+`)
			AND EXISTS (SELECT 1 FROM runs r WHERE r.task_id = t.id AND r.kind = 'archive_import')`, parentID).Scan(&exists); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "task_query_failed"})
			return
		}
		if exists == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "archive_import_not_found"})
			return
		}
		joins = ` JOIN archive_entries entry ON entry.created_task_id = t.id
		 JOIN runs parent_run ON parent_run.id = entry.import_run_id AND parent_run.kind = 'archive_import'`
		archivePath = "entry.logical_path"
		conditions = []string{"t.deleted_at IS NULL", "parent_run.task_id = ?"}
		args = append(args, parentID)
	}
	recordConditions, recordArgs := taskRecordFilters(options, "t", func() string {
		if parentID != "" {
			return archivePath
		}
		return ""
	}())
	if len(recordConditions) > 0 {
		match := "(" + strings.Join(recordConditions, " AND ") + ")"
		args = append(args, recordArgs...)
		if parentID == "" {
			childConditions, childArgs := taskRecordFilters(options, "filter_child", "filter_entry.logical_path")
			match = "(" + match + ` OR EXISTS (SELECT 1 FROM runs filter_run
			 JOIN archive_entries filter_entry ON filter_entry.import_run_id = filter_run.id
			 JOIN tasks filter_child ON filter_child.id = filter_entry.created_task_id AND filter_child.deleted_at IS NULL
			 WHERE filter_run.task_id = t.id AND filter_run.kind = 'archive_import' AND ` + strings.Join(childConditions, " AND ") + "))"
			args = append(args, childArgs...)
		}
		conditions = append(conditions, match)
	}
	if options.AnalysisMode != "" {
		conditions = append(conditions, "COALESCE(t.analysis_mode, t.input_category, 'binary') = ?")
		args = append(args, options.AnalysisMode)
	}
	if options.Creator != "" {
		conditions = append(conditions, "(LOWER(u.username) LIKE ? OR LOWER(u.public_id) = ?)")
		args = append(args, "%"+strings.ToLower(options.Creator)+"%", strings.ToLower(options.Creator))
	}
	if options.CreatedFrom != nil {
		conditions = append(conditions, "t.created_at >= ?")
		args = append(args, *options.CreatedFrom)
	}
	if options.CreatedTo != nil {
		conditions = append(conditions, "t.created_at < ?")
		args = append(args, *options.CreatedTo)
	}
	if options.Cursor != "" {
		var cursorCreated time.Time
		cursorQuery := `SELECT t.created_at FROM tasks t` + joins + ` WHERE t.id = ? AND `
		cursorArgs := []any{options.Cursor}
		if parentID == "" {
			cursorQuery += taskRootVisibility
		} else {
			cursorQuery += "t.deleted_at IS NULL AND parent_run.task_id = ?"
			cursorArgs = append(cursorArgs, parentID)
		}
		if err := s.db.QueryRowContext(c, cursorQuery, cursorArgs...).Scan(&cursorCreated); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_task_list_cursor"})
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "task_query_failed"})
			}
			return
		}
		conditions = append(conditions, "(t.created_at < ? OR (t.created_at = ? AND t.id < ?))")
		args = append(args, cursorCreated, cursorCreated, options.Cursor)
	}
	query := `SELECT t.id, t.display_name, t.status, u.public_id, u.username, HEX(b.sha256),
	 t.input_category, COALESCE(t.analysis_mode, t.input_category), t.detected_category,
	 t.detected_format, t.created_at, t.updated_at, ` + archivePath + `, ` + taskExecutionStatusSQL("t") + `
	 FROM tasks t JOIN blobs b ON b.id = t.blob_id JOIN users u ON u.id = t.created_by` + joins + `
	 WHERE ` + strings.Join(conditions, " AND ") + ` ORDER BY t.created_at DESC, t.id DESC LIMIT ?`
	args = append(args, options.PageSize+1)
	rows, err := s.db.QueryContext(c, query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "task_query_failed"})
		return
	}
	tasks := make([]taskSummary, 0, options.PageSize+1)
	for rows.Next() {
		var item taskSummary
		var inputCategory, analysisMode, detectedCategory, detected sql.NullString
		if err = rows.Scan(&item.ID, &item.DisplayName, &item.Status, &item.CreatorID, &item.CreatorName, &item.InputSHA256,
			&inputCategory, &analysisMode, &detectedCategory, &detected, &item.CreatedAt, &item.UpdatedAt, &item.ArchivePath, &item.ExecutionStatus); err != nil {
			break
		}
		item.InputCategory, item.AnalysisMode = inputCategory.String, analysisMode.String
		item.DetectedCategory, item.DetectedFormat = detectedCategory.String, detected.String
		item.InputSHA256 = strings.ToLower(item.InputSHA256)
		tasks = append(tasks, item)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "task_query_failed"})
		return
	}
	response := gin.H{}
	if len(tasks) > options.PageSize {
		response["next_cursor"] = tasks[options.PageSize-1].ID
		tasks = tasks[:options.PageSize]
	}
	if parentID == "" {
		if err := s.attachTaskArchives(c, tasks); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "task_query_failed"})
			return
		}
	}
	response["tasks"] = tasks
	c.JSON(http.StatusOK, response)
}

func (s *taskService) attachTaskArchives(ctx context.Context, tasks []taskSummary) error {
	if len(tasks) == 0 {
		return nil
	}
	args := make([]any, 0, len(tasks))
	byID := make(map[string]*taskSummary, len(tasks))
	for i := range tasks {
		args = append(args, tasks[i].ID)
		byID[tasks[i].ID] = &tasks[i]
	}
	rows, err := s.db.QueryContext(ctx, `SELECT t.id, COALESCE(t.upload_id, t.id), t.deleted_at IS NULL,
	 latest.id, latest.status, COUNT(child.id),
	 COALESCE(SUM(child.execution_status = 'SCAN_COMPLETED'), 0),
	 COALESCE(SUM(child.execution_status IN ('PREPARING', 'DECOMPILING', 'SCANNING')), 0),
	 COALESCE(SUM(child.execution_status IN ('FAILED', 'SCAN_FAILED', 'DECOMPILE_FAILED')), 0)
	 FROM tasks t JOIN runs latest ON latest.id = (SELECT r.id FROM runs r
	 WHERE r.task_id = t.id AND r.kind = 'archive_import'
	 AND (t.deleted_at IS NULL OR EXISTS (SELECT 1 FROM archive_entries kept_entry
	 JOIN tasks kept_child ON kept_child.id = kept_entry.created_task_id AND kept_child.deleted_at IS NULL
	 WHERE kept_entry.import_run_id = r.id) OR EXISTS (SELECT 1 FROM archive_report_bundles kept_bundle
	 WHERE kept_bundle.import_run_id = r.id AND kept_bundle.status = 'ready' AND kept_bundle.deleted_at IS NULL))
	 ORDER BY r.created_at DESC, r.id DESC LIMIT 1)
	 LEFT JOIN runs history ON history.task_id = t.id AND history.kind = 'archive_import'
	 LEFT JOIN archive_entries entry ON entry.import_run_id = history.id
	 LEFT JOIN (SELECT execution_child.id, `+taskExecutionStatusSQL("execution_child")+` AS execution_status
	 FROM tasks execution_child WHERE execution_child.deleted_at IS NULL) child ON child.id = entry.created_task_id
	 WHERE t.id IN (`+strings.TrimSuffix(strings.Repeat("?,", len(args)), ",")+`)
	 GROUP BY t.id, t.upload_id, t.deleted_at, latest.id, latest.status`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, runStatus string
		var archive taskArchiveSummary
		if err := rows.Scan(&id, &archive.UploadID, &archive.SourceRetained, &archive.ImportID, &runStatus,
			&archive.ChildCount, &archive.CompletedCount, &archive.ActiveCount, &archive.FailedCount); err != nil {
			return err
		}
		archive.Status = archiveImportStatus(runStatus)
		byID[id].Archive = &archive
	}
	return rows.Err()
}
