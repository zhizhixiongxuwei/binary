package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"binaryscan.local/backend/internal/filetype"
	"binaryscan.local/backend/internal/identity"

	"github.com/gin-gonic/gin"
)

type archiveImportRecord struct {
	ID              string    `json:"id"`
	UploadID        string    `json:"upload_id"`
	Filename        string    `json:"filename"`
	Status          string    `json:"status"`
	ScannedEntries  int       `json:"scanned_entries"`
	TotalEntries    int       `json:"total_entries"`
	EligibleEntries int       `json:"eligible_entries"`
	SkippedEntries  int       `json:"skipped_entries"`
	CreatedTasks    int       `json:"created_tasks"`
	ErrorCode       string    `json:"error_code,omitempty"`
	ErrorMessage    string    `json:"error_message,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

func (s *taskService) listArchiveImports(c *gin.Context) {
	pageSize := boundedPageSize(c.Query("page_size"), 50, 100)
	cursorID := strings.TrimSpace(c.Query("cursor"))
	var rows *sql.Rows
	var err error
	if cursorID == "" {
		rows, err = s.db.QueryContext(c, `SELECT r.id FROM runs r
			JOIN tasks t ON t.id = r.task_id AND t.deleted_at IS NULL
			WHERE r.kind = 'archive_import'
			  AND NOT EXISTS (SELECT 1 FROM runs newer WHERE newer.task_id = r.task_id
				AND newer.kind = 'archive_import'
				AND (newer.created_at > r.created_at OR (newer.created_at = r.created_at AND newer.id > r.id)))
			ORDER BY r.created_at DESC, r.id DESC LIMIT ?`, pageSize+1)
	} else {
		var cursorCreated time.Time
		if queryErr := s.db.QueryRowContext(c, `SELECT created_at FROM runs
			WHERE id = ? AND kind = 'archive_import'`, cursorID).Scan(&cursorCreated); queryErr != nil {
			if errors.Is(queryErr, sql.ErrNoRows) {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_archive_import_cursor"})
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "archive_import_query_failed"})
			}
			return
		}
		rows, err = s.db.QueryContext(c, `SELECT r.id FROM runs r
			JOIN tasks t ON t.id = r.task_id AND t.deleted_at IS NULL
			WHERE r.kind = 'archive_import'
			  AND (r.created_at < ? OR (r.created_at = ? AND r.id < ?))
			  AND NOT EXISTS (SELECT 1 FROM runs newer WHERE newer.task_id = r.task_id
				AND newer.kind = 'archive_import'
				AND (newer.created_at > r.created_at OR (newer.created_at = r.created_at AND newer.id > r.id)))
			ORDER BY r.created_at DESC, r.id DESC LIMIT ?`, cursorCreated, cursorCreated, cursorID, pageSize+1)
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "archive_import_query_failed"})
		return
	}
	defer rows.Close()
	ids := make([]string, 0, pageSize+1)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "archive_import_query_failed"})
			return
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "archive_import_query_failed"})
		return
	}
	response := gin.H{}
	if len(ids) > pageSize {
		response["next_cursor"] = ids[pageSize-1]
		ids = ids[:pageSize]
	}
	items := make([]archiveImportRecord, 0, len(ids))
	for _, id := range ids {
		item, err := s.loadArchiveImport(c, id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "archive_import_query_failed"})
			return
		}
		items = append(items, item)
	}
	response["items"] = items
	c.JSON(http.StatusOK, response)
}

func (s *taskService) getArchiveImport(c *gin.Context) {
	item, err := s.loadArchiveImport(c, c.Param("importID"))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "archive_import_not_found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "archive_import_query_failed"})
		}
		return
	}
	c.JSON(http.StatusOK, item)
}

func (s *taskService) loadArchiveImport(ctx context.Context, importID string) (archiveImportRecord, error) {
	var result archiveImportRecord
	var runStatus string
	var errorCode, errorMessage sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT r.id, COALESCE(t.upload_id, t.id), t.display_name,
		r.status, r.error_code, r.error_message, r.created_at,
		COALESCE(r.completed_at, r.started_at, r.created_at)
		FROM runs r JOIN tasks t ON t.id = r.task_id AND t.deleted_at IS NULL
		WHERE r.id = ? AND r.kind = 'archive_import'`, importID).Scan(
		&result.ID, &result.UploadID, &result.Filename, &runStatus, &errorCode,
		&errorMessage, &result.CreatedAt, &result.UpdatedAt,
	)
	if err != nil {
		return archiveImportRecord{}, err
	}
	result.Status = archiveImportStatus(runStatus)
	result.ErrorCode, result.ErrorMessage = errorCode.String, errorMessage.String
	rows, err := s.db.QueryContext(ctx, `SELECT detected_format, status, created_task_id
		FROM archive_entries WHERE import_run_id = ? ORDER BY ordinal`, importID)
	if err != nil {
		return archiveImportRecord{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var detected, createdTask sql.NullString
		var status string
		if err := rows.Scan(&detected, &status, &createdTask); err != nil {
			return archiveImportRecord{}, err
		}
		result.ScannedEntries++
		result.TotalEntries++
		category, supported := filetype.CategoryForFormat(detected.String)
		if supported && category == filetype.CategoryBinary && status != "skipped" && status != "failed" {
			result.EligibleEntries++
			if createdTask.Valid {
				result.CreatedTasks++
			}
		} else {
			result.SkippedEntries++
		}
	}
	if err := rows.Err(); err != nil {
		return archiveImportRecord{}, err
	}
	return result, nil
}

func archiveImportStatus(value string) string {
	switch value {
	case "queued":
		return "queued"
	case "running":
		return "running"
	case "complete", "partial":
		return "ready"
	case "unsupported":
		return "unsupported"
	default:
		return "failed"
	}
}

type archiveEntryResponse struct {
	ID               string  `json:"id"`
	Path             string  `json:"path"`
	SizeBytes        uint64  `json:"size_bytes"`
	SHA256           *string `json:"sha256"`
	DetectedFormat   *string `json:"detected_format"`
	DetectedCategory *string `json:"detected_category"`
	Status           string  `json:"status"`
	SkipReason       string  `json:"skip_reason,omitempty"`
	TaskID           string  `json:"task_id,omitempty"`
}

func (s *taskService) listArchiveImportEntries(c *gin.Context) {
	importID := c.Param("importID")
	if _, err := s.loadArchiveImport(c, importID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "archive_import_not_found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "archive_import_query_failed"})
		}
		return
	}
	filter := strings.TrimSpace(c.Query("filter"))
	if filter == "" {
		filter = "all"
	}
	if filter != "all" && filter != "eligible" && filter != "skipped" && filter != "created" && filter != "failed" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_archive_entry_filter"})
		return
	}
	cursor := uint64(0)
	if raw := strings.TrimSpace(c.Query("cursor")); raw != "" {
		value, err := strconv.ParseUint(raw, 10, 64)
		if err != nil || value == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_archive_entry_cursor"})
			return
		}
		cursor = value
	}
	pageSize := boundedPageSize(c.Query("page_size"), 50, 100)
	rows, err := s.db.QueryContext(c, `SELECT ae.id, ae.logical_path, ae.size_bytes,
		HEX(b.sha256), ae.detected_format, ae.status, ae.created_task_id
		FROM archive_entries ae LEFT JOIN blobs b ON b.id = ae.blob_id
		WHERE ae.import_run_id = ? AND ae.id > ? ORDER BY ae.id LIMIT 20000`, importID, cursor)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "archive_entry_query_failed"})
		return
	}
	defer rows.Close()
	items := make([]archiveEntryResponse, 0, pageSize+1)
	for rows.Next() {
		var id, size uint64
		var logicalPath, storedStatus string
		var sha, detected, createdTask sql.NullString
		if err := rows.Scan(&id, &logicalPath, &size, &sha, &detected, &storedStatus, &createdTask); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "archive_entry_query_failed"})
			return
		}
		entry := mapArchiveEntry(id, logicalPath, size, sha, detected, storedStatus, createdTask)
		if filter != "all" && entry.Status != filter {
			continue
		}
		items = append(items, entry)
		if len(items) > pageSize {
			break
		}
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "archive_entry_query_failed"})
		return
	}
	response := gin.H{"items": items}
	if len(items) > pageSize {
		response["items"] = items[:pageSize]
		response["next_cursor"] = items[pageSize-1].ID
	}
	c.JSON(http.StatusOK, response)
}

func mapArchiveEntry(
	id uint64, logicalPath string, size uint64, sha, detected sql.NullString,
	storedStatus string, createdTask sql.NullString,
) archiveEntryResponse {
	entry := archiveEntryResponse{ID: strconv.FormatUint(id, 10), Path: logicalPath, SizeBytes: size, Status: "skipped"}
	if sha.Valid && sha.String != "" {
		value := strings.ToLower(sha.String)
		entry.SHA256 = &value
	}
	if detected.Valid && detected.String != "" {
		value := detected.String
		entry.DetectedFormat = &value
	}
	category, supported := filetype.CategoryForFormat(detected.String)
	if supported && (category == filetype.CategoryBinary || category == filetype.CategoryContainer) {
		value := string(category)
		entry.DetectedCategory = &value
	}
	if storedStatus == "failed" && category == filetype.CategoryBinary && entry.SHA256 != nil {
		entry.Status = "failed"
		entry.SkipReason = "归档成员处理失败"
		return entry
	}
	if storedStatus != "skipped" && category == filetype.CategoryBinary && entry.SHA256 != nil {
		if createdTask.Valid {
			entry.Status = "created"
			entry.TaskID = createdTask.String
		} else {
			entry.Status = "eligible"
		}
		return entry
	}
	switch category {
	case filetype.CategoryContainer:
		entry.SkipReason = "容器镜像需作为容器任务单独上传"
	case filetype.CategoryArchive:
		entry.SkipReason = "嵌套归档仅列出，不递归拆包"
	default:
		if storedStatus == "skipped" {
			entry.SkipReason = "非普通文件或空文件"
		} else {
			entry.SkipReason = "不是受支持的二进制文件"
		}
	}
	return entry
}

type archiveTaskBatchRequest struct {
	EntryIDs []string `json:"entry_ids" binding:"required,min=1,max=10"`
}

func (s *taskService) createArchiveTaskBatch(c *gin.Context) {
	idempotencyKey := strings.TrimSpace(c.GetHeader("Idempotency-Key"))
	if idempotencyKey == "" || len(idempotencyKey) > 128 || strings.ContainsRune(idempotencyKey, '\x00') {
		c.JSON(http.StatusBadRequest, gin.H{"error": "idempotency_key_required"})
		return
	}
	var request archiveTaskBatchRequest
	if err := c.ShouldBindJSON(&request); err != nil || len(request.EntryIDs) == 0 || len(request.EntryIDs) > 10 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_archive_task_batch"})
		return
	}
	seen := make(map[string]struct{}, len(request.EntryIDs))
	for _, rawID := range request.EntryIDs {
		value, err := strconv.ParseUint(rawID, 10, 64)
		if err != nil || value == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_archive_task_batch"})
			return
		}
		if _, duplicate := seen[rawID]; duplicate {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_archive_task_batch"})
			return
		}
		seen[rawID] = struct{}{}
	}
	items := make([]gin.H, 0, len(request.EntryIDs))
	for _, entryID := range request.EntryIDs {
		taskID, created, err := s.createTaskFromArchiveEntry(c, c.Param("importID"), entryID,
			mustCurrentUser(c).ID, idempotencyKey)
		if err != nil {
			code := "archive_entry_not_eligible"
			if errors.Is(err, sql.ErrNoRows) {
				code = "archive_entry_not_found"
			} else if !errors.Is(err, errArchiveEntryNotEligible) {
				code = "archive_task_creation_failed"
				slog.Error("create archive child task failed", "request_id", c.GetString("requestID"),
					"import_id", c.Param("importID"), "entry_id", entryID, "error", err)
			}
			items = append(items, gin.H{"entry_id": entryID, "outcome": "failed", "error_code": code,
				"message": "无法为该归档成员创建二进制任务"})
			continue
		}
		outcome := "existing"
		if created {
			outcome = "created"
		}
		items = append(items, gin.H{"entry_id": entryID, "outcome": outcome, "task_id": taskID})
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
}

var errArchiveEntryNotEligible = errors.New("archive entry is not an eligible binary")

func (s *taskService) createTaskFromArchiveEntry(
	ctx *gin.Context, importID, entryID string, userID uint64, batchKey string,
) (string, bool, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return "", false, err
	}
	defer tx.Rollback()
	var parentTaskID, logicalPath, storedStatus string
	var detected, blobID, existingTask sql.NullString
	var size uint64
	var ownerID uint64
	err = tx.QueryRowContext(ctx, `SELECT r.task_id, t.created_by, ae.logical_path, ae.size_bytes,
		ae.detected_format, ae.status, ae.blob_id, ae.created_task_id
		FROM archive_entries ae
		JOIN runs r ON r.id = ae.import_run_id AND r.kind = 'archive_import'
		JOIN tasks t ON t.id = r.task_id AND t.deleted_at IS NULL
		WHERE ae.import_run_id = ? AND ae.id = ? FOR UPDATE`, importID, entryID).Scan(
		&parentTaskID, &ownerID, &logicalPath, &size, &detected, &storedStatus, &blobID, &existingTask,
	)
	if err != nil {
		return "", false, err
	}
	if existingTask.Valid {
		return existingTask.String, false, nil
	}
	category, supported := filetype.CategoryForFormat(detected.String)
	if !supported || category != filetype.CategoryBinary || !blobID.Valid || storedStatus != "materialized" {
		return "", false, errArchiveEntryNotEligible
	}
	taskID, err := identity.UUID()
	if err != nil {
		return "", false, err
	}
	fileID, err := identity.UUID()
	if err != nil {
		return "", false, err
	}
	runID, err := identity.UUID()
	if err != nil {
		return "", false, err
	}
	displayName := path.Base(logicalPath)
	if displayName == "." || displayName == "/" || displayName == "" {
		displayName = logicalPath
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO tasks
		(id, created_by, blob_id, display_name, input_category, analysis_mode, detected_category, detected_format, status)
		VALUES (?, ?, ?, ?, 'binary', 'binary', 'binary', ?, 'queued')`,
		taskID, ownerID, blobID.String, displayName, detected.String); err != nil {
		return "", false, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO file_nodes
		(id, task_id, blob_id, logical_path, node_kind, detected_format, size_bytes)
		VALUES (?, ?, ?, ?, 'file', ?, ?)`, fileID, taskID, blobID.String, logicalPath, detected.String, size); err != nil {
		return "", false, err
	}
	request, _ := json.Marshal(map[string]string{"source": "archive", "archiveImportId": importID, "archiveEntryId": entryID})
	if _, err := tx.ExecContext(ctx, `INSERT INTO runs
		(id, kind, status, task_id, subject_type, subject_id, created_by, idempotency_key, request)
		VALUES (?, 'scan', 'queued', ?, 'task', ?, ?, ?, ?)`,
		runID, taskID, taskID, ownerID, "archive-entry:"+importID+":"+entryID, request); err != nil {
		return "", false, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO jobs (run_id, kind, status, max_attempts)
		VALUES (?, 'scan', 'queued', 3)`, runID); err != nil {
		return "", false, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE archive_entries
		SET status = 'task_created', created_task_id = ? WHERE import_run_id = ? AND id = ?`,
		taskID, importID, entryID); err != nil {
		return "", false, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO task_events
		(task_id, event_type, message) VALUES (?, 'archive.child.created', ?)`, taskID,
		"由归档成员创建，基础扫描已排队"); err != nil {
		return "", false, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_logs
		(actor_user_id, action, object_type, object_id, request_id, client_ip, outcome, details)
		VALUES (?, 'archive.task.create', 'task', ?, ?, ?, 'success',
			JSON_OBJECT('archiveImportId', ?, 'archiveEntryId', ?, 'parentTaskId', ?, 'batchKey', ?))`,
		userID, taskID, ctx.GetString("requestID"), ctx.ClientIP(), importID, entryID, parentTaskID, batchKey); err != nil {
		return "", false, err
	}
	if err := tx.Commit(); err != nil {
		return "", false, err
	}
	return taskID, true, nil
}

func boundedPageSize(raw string, fallback, maximum int) int {
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || value <= 0 {
		return fallback
	}
	if value > maximum {
		return maximum
	}
	return value
}
