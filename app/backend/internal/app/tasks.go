package app

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"binaryscan.local/backend/internal/config"
	"binaryscan.local/backend/internal/filetype"
	"binaryscan.local/backend/internal/identity"
	"binaryscan.local/backend/internal/job"
	"binaryscan.local/backend/internal/storage"

	"github.com/gin-gonic/gin"
)

type taskService struct {
	db             *sql.DB
	blobs          *storage.BlobStore
	uploadMaxBytes int64
	storageRoot    string
	reportRoot     string
}

type taskSummary struct {
	ID               string    `json:"id"`
	DisplayName      string    `json:"displayName"`
	Status           string    `json:"status"`
	InputSHA256      string    `json:"inputSha256,omitempty"`
	InputCategory    string    `json:"inputCategory,omitempty"`
	DetectedCategory string    `json:"detectedCategory,omitempty"`
	DetectedFormat   string    `json:"detectedFormat,omitempty"`
	CreatedAt        time.Time `json:"createdAt"`
	UpdatedAt        time.Time `json:"updatedAt"`
}

type queuedRun struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"createdAt"`
}

const taskRunsQuery = `SELECT id, kind, status, subject_type, subject_id, result_quality,
        tool_name, tool_version, ruleset_version, error_code, error_message, created_at, started_at, completed_at
        FROM runs WHERE task_id = ? ORDER BY created_at DESC LIMIT 100`

type taskRunRowScanner interface {
	Scan(dest ...any) error
}

func newTaskService(cfg config.Config, db *sql.DB) (*taskService, error) {
	blobs, err := storage.NewBlobStore(path.Join(cfg.App.StorageRoot, "blobs"))
	if err != nil {
		return nil, err
	}
	reportRoot := filepath.Join(cfg.App.StorageRoot, "reports")
	if err := os.MkdirAll(filepath.Join(reportRoot, ".staging"), 0o700); err != nil {
		return nil, fmt.Errorf("create report storage: %w", err)
	}
	return &taskService{db: db, blobs: blobs, uploadMaxBytes: cfg.App.UploadMaxBytes,
		storageRoot: cfg.App.StorageRoot, reportRoot: reportRoot}, nil
}

func (s *taskService) create(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, s.uploadMaxBytes+(1<<20))
	reader, err := c.Request.MultipartReader()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "multipart_file_required"})
		return
	}

	var blob storage.Blob
	var originalName string
	var requestedCategory filetype.Category
	seenFile, seenCategory := false, false
	for {
		part, nextErr := reader.NextPart()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_multipart_upload"})
			return
		}
		switch part.FormName() {
		case "input_category":
			if part.FileName() != "" || seenCategory {
				part.Close()
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_input_category"})
				return
			}
			seenCategory = true
			body, readErr := io.ReadAll(io.LimitReader(part, 65))
			part.Close()
			var ok bool
			requestedCategory, ok = filetype.ParseCategory(string(body))
			if readErr != nil || len(body) > 64 || !ok {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_input_category"})
				return
			}
		case "file":
			if part.FileName() == "" || seenFile {
				part.Close()
				c.JSON(http.StatusBadRequest, gin.H{"error": "single_file_required"})
				return
			}
			seenFile = true
			originalName, err = cleanUploadName(part.FileName())
			if err == nil {
				blob, err = s.blobs.Ingest(part, s.uploadMaxBytes)
			}
			part.Close()
			if err != nil {
				if errors.Is(err, storage.ErrBlobTooLarge) {
					c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "upload_too_large"})
				} else {
					c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_upload"})
				}
				return
			}
		default:
			part.Close()
			c.JSON(http.StatusBadRequest, gin.H{"error": "unexpected_multipart_field"})
			return
		}
	}
	if !seenFile {
		c.JSON(http.StatusBadRequest, gin.H{"error": "file_required"})
		return
	}
	if !seenCategory {
		c.JSON(http.StatusBadRequest, gin.H{"error": "input_category_required"})
		return
	}
	blobPath := filepath.Join(s.storageRoot, "blobs", filepath.FromSlash(blob.StorageKey))
	detected, err := filetype.Detect(blobPath, originalName)
	if err != nil {
		slog.Error("server-side input detection failed", "request_id", c.GetString("requestID"), "error", err)
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "unsupported_input_format"})
		return
	}
	if detected.Category == "" || detected.Format == "unknown" {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "unsupported_input_format"})
		return
	}
	if detected.Category != requestedCategory {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "input_category_mismatch",
			"detectedCategory": detected.Category, "detectedFormat": detected.Format})
		return
	}

	user := mustCurrentUser(c)
	task, err := s.persistUpload(c, user.ID, originalName, blob, requestedCategory, detected)
	if err != nil {
		slog.Error("persist upload failed", "request_id", c.GetString("requestID"), "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "task_creation_failed"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"task": task})
}

func (s *taskService) persistUpload(
	ctx *gin.Context, userID uint64, name string, blob storage.Blob,
	inputCategory filetype.Category, detected filetype.Result,
) (taskSummary, error) {
	uploadID, err := identity.UUID()
	if err != nil {
		return taskSummary{}, err
	}
	taskID, err := identity.UUID()
	if err != nil {
		return taskSummary{}, err
	}
	fileID, err := identity.UUID()
	if err != nil {
		return taskSummary{}, err
	}
	runID, err := identity.UUID()
	if err != nil {
		return taskSummary{}, err
	}
	blobID, err := identity.UUID()
	if err != nil {
		return taskSummary{}, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return taskSummary{}, fmt.Errorf("begin upload transaction: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO blobs
        (id, sha256, size_bytes, storage_key, state)
        VALUES (?, ?, ?, ?, 'ready')
        ON DUPLICATE KEY UPDATE state = 'ready', deleted_at = NULL`,
		blobID, blob.SHA256[:], blob.SizeBytes, blob.StorageKey); err != nil {
		return taskSummary{}, fmt.Errorf("persist blob: %w", err)
	}
	if err := tx.QueryRowContext(ctx, "SELECT id FROM blobs WHERE sha256 = ?", blob.SHA256[:]).Scan(&blobID); err != nil {
		return taskSummary{}, fmt.Errorf("resolve blob identity: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO uploads
		(id, created_by, original_name, input_category, content_type, declared_size, received_size, status,
		 validation_status, detected_category, detected_format, blob_id, completed_at, expires_at)
		VALUES (?, ?, ?, ?, 'application/octet-stream', ?, ?, 'complete', 'valid', ?, ?, ?,
			UTC_TIMESTAMP(6), DATE_ADD(UTC_TIMESTAMP(6), INTERVAL 1 DAY))`,
		uploadID, userID, name, inputCategory, blob.SizeBytes, blob.SizeBytes,
		detected.Category, detected.Format, blobID); err != nil {
		return taskSummary{}, fmt.Errorf("persist upload: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO tasks
		(id, created_by, upload_id, blob_id, display_name, input_category, detected_category, detected_format, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'queued')`,
		taskID, userID, uploadID, blobID, name, inputCategory, detected.Category, detected.Format); err != nil {
		return taskSummary{}, fmt.Errorf("create task: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO file_nodes
		(id, task_id, blob_id, logical_path, node_kind, detected_format, size_bytes)
		VALUES (?, ?, ?, ?, 'file', ?, ?)`, fileID, taskID, blobID, name, detected.Format, blob.SizeBytes); err != nil {
		return taskSummary{}, fmt.Errorf("create root file: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO runs
        (id, kind, status, task_id, subject_type, subject_id, created_by, idempotency_key, request)
		VALUES (?, 'scan', 'queued', ?, 'task', ?, ?, ?,
			JSON_OBJECT('source', 'upload', 'inputCategory', ?, 'detectedFormat', ?))`,
		runID, taskID, taskID, userID, taskID, inputCategory, detected.Format); err != nil {
		return taskSummary{}, fmt.Errorf("create scan run: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO jobs (run_id, kind, status, max_attempts)
        VALUES (?, 'scan', 'queued', 3)`, runID); err != nil {
		return taskSummary{}, fmt.Errorf("enqueue scan: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO task_events
        (task_id, event_type, message) VALUES (?, 'upload.complete', '基础扫描已排队')`, taskID); err != nil {
		return taskSummary{}, fmt.Errorf("record upload event: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_logs
        (actor_user_id, action, object_type, object_id, request_id, client_ip, outcome, details)
		VALUES (?, 'task.create', 'task', ?, ?, ?, 'success',
			JSON_OBJECT('displayName', ?, 'inputCategory', ?, 'detectedFormat', ?))`,
		userID, taskID, ctx.GetString("requestID"), ctx.ClientIP(), name, inputCategory, detected.Format); err != nil {
		return taskSummary{}, fmt.Errorf("audit task creation: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return taskSummary{}, fmt.Errorf("commit upload: %w", err)
	}
	return taskSummary{ID: taskID, DisplayName: name, Status: "queued", InputCategory: string(inputCategory),
		InputSHA256: fmt.Sprintf("%x", blob.SHA256), DetectedCategory: string(detected.Category), DetectedFormat: detected.Format,
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}, nil
}

func (s *taskService) list(c *gin.Context) {
	limit := 50
	if raw := c.Query("limit"); raw != "" {
		if value, err := strconv.Atoi(raw); err == nil && value > 0 && value <= 100 {
			limit = value
		}
	}
	rows, err := s.db.QueryContext(c, `SELECT t.id, t.display_name, t.status, HEX(b.sha256),
		t.input_category, t.detected_category, t.detected_format, t.created_at, t.updated_at
		FROM tasks t JOIN blobs b ON b.id = t.blob_id
		WHERE t.deleted_at IS NULL AND COALESCE(t.input_category, 'binary') <> 'archive'
		ORDER BY t.created_at DESC LIMIT ?`, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "task_query_failed"})
		return
	}
	defer rows.Close()
	tasks := make([]taskSummary, 0)
	for rows.Next() {
		var item taskSummary
		var inputCategory, detectedCategory, detected sql.NullString
		if err := rows.Scan(&item.ID, &item.DisplayName, &item.Status, &item.InputSHA256,
			&inputCategory, &detectedCategory,
			&detected, &item.CreatedAt, &item.UpdatedAt); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "task_query_failed"})
			return
		}
		item.InputCategory = inputCategory.String
		item.DetectedCategory = detectedCategory.String
		item.DetectedFormat = detected.String
		item.InputSHA256 = strings.ToLower(item.InputSHA256)
		tasks = append(tasks, item)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "task_query_failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"tasks": tasks})
}

func (s *taskService) get(c *gin.Context) {
	taskID := c.Param("taskID")
	var task taskSummary
	var inputCategory, detectedCategory, detected sql.NullString
	if err := s.db.QueryRowContext(c, `SELECT t.id, t.display_name, t.status, HEX(b.sha256),
		t.input_category, t.detected_category, t.detected_format, t.created_at, t.updated_at
		FROM tasks t JOIN blobs b ON b.id = t.blob_id
		WHERE t.id = ? AND t.deleted_at IS NULL`, taskID).Scan(
		&task.ID, &task.DisplayName, &task.Status, &task.InputSHA256, &inputCategory, &detectedCategory,
		&detected, &task.CreatedAt, &task.UpdatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "task_not_found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "task_query_failed"})
		}
		return
	}
	task.InputCategory = inputCategory.String
	task.DetectedCategory = detectedCategory.String
	task.DetectedFormat = detected.String
	task.InputSHA256 = strings.ToLower(task.InputSHA256)

	files, err := s.queryFiles(c, taskID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "task_query_failed"})
		return
	}
	runs, err := s.queryRuns(c, taskID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "task_query_failed"})
		return
	}
	projects, err := s.queryProjects(c, taskID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "task_query_failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"task": task, "files": files, "runs": runs, "projects": projects})
}

func (s *taskService) findings(c *gin.Context) {
	taskID := c.Param("taskID")
	runID := strings.TrimSpace(c.Query("runId"))
	limit := 500
	if raw := c.Query("limit"); raw != "" {
		if value, err := strconv.Atoi(raw); err == nil && value > 0 && value <= 1000 {
			limit = value
		}
	}
	rows, err := s.db.QueryContext(c, `SELECT id, run_id, source_project_id, source_file_id,
		finding_type, language, severity, rule_id, cwe, external_id, logical_path,
		start_line, start_column, end_line, end_column, title, message, snippet, snippet_start_line, details, created_at
        FROM findings WHERE task_id = ? AND (? = '' OR run_id = ?)
        ORDER BY FIELD(severity, 'critical', 'high', 'medium', 'low', 'info'), id LIMIT ?`,
		taskID, runID, runID, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "finding_query_failed"})
		return
	}
	defer rows.Close()
	result := make([]gin.H, 0)
	for rows.Next() {
		var id uint64
		var foundRunID, findingType, severity, title, message string
		var sourceProjectID, sourceFileID, language, ruleID, cwe, externalID, logicalPath, snippet sql.NullString
		var line, column, endLine, endColumn, snippetStartLine sql.NullInt64
		var details []byte
		var created time.Time
		if err := rows.Scan(&id, &foundRunID, &sourceProjectID, &sourceFileID, &findingType, &language,
			&severity, &ruleID, &cwe, &externalID, &logicalPath, &line, &column, &endLine, &endColumn,
			&title, &message, &snippet, &snippetStartLine, &details, &created); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "finding_query_failed"})
			return
		}
		var evidence any
		if len(details) != 0 {
			_ = json.Unmarshal(details, &evidence)
		}
		result = append(result, gin.H{"id": id, "runId": foundRunID, "type": findingType,
			"sourceProjectId": nullableString(sourceProjectID), "sourceFileId": nullableString(sourceFileID),
			"language": nullableString(language), "severity": severity, "ruleId": nullableString(ruleID),
			"cwe": nullableString(cwe), "externalId": nullableString(externalID), "path": nullableString(logicalPath),
			"line": nullableInt(line), "column": nullableInt(column), "title": title, "message": message,
			"startLine": nullableInt(line), "startColumn": nullableInt(column),
			"endLine": nullableInt(endLine), "endColumn": nullableInt(endColumn),
			"snippet": nullableString(snippet), "snippetStartLine": nullableInt(snippetStartLine),
			"evidence": evidence, "createdAt": created})
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "finding_query_failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"findings": result})
}

func (s *taskService) delete(c *gin.Context) {
	taskID := c.Param("taskID")
	user := mustCurrentUser(c)
	tx, err := s.db.BeginTx(c, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "task_deletion_failed"})
		return
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(c, `UPDATE tasks SET status = 'deleted', deleted_at = UTC_TIMESTAMP(6)
		WHERE id = ? AND deleted_at IS NULL`, taskID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "task_deletion_failed"})
		return
	}
	changed, err := result.RowsAffected()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "task_deletion_failed"})
		return
	}
	if changed == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "task_not_found"})
		return
	}
	if _, err := tx.ExecContext(c, `INSERT INTO task_events
		(task_id, event_type, message) VALUES (?, 'task.deleted', '任务已删除')`, taskID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "task_deletion_failed"})
		return
	}
	if _, err := tx.ExecContext(c, `INSERT INTO audit_logs
		(actor_user_id, action, object_type, object_id, request_id, client_ip, outcome, details)
		VALUES (?, 'task.delete', 'task', ?, ?, ?, 'success', JSON_OBJECT())`,
		user.ID, taskID, c.GetString("requestID"), c.ClientIP()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "task_deletion_failed"})
		return
	}
	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "task_deletion_failed"})
		return
	}
	c.Status(http.StatusNoContent)
}

func (s *taskService) queueDecompile(c *gin.Context) {
	taskID, fileID := c.Param("taskID"), c.Param("fileID")
	var detected sql.NullString
	if err := s.db.QueryRowContext(c, `SELECT detected_format FROM file_nodes
        WHERE id = ? AND task_id = ? AND node_kind = 'file'`, fileID, taskID).Scan(&detected); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "file_not_found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "file_query_failed"})
		}
		return
	}
	kind, ok := decompileKind(detected.String)
	if !ok {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "decompile_not_supported"})
		return
	}
	s.queueManualRun(c, taskID, "file_node", fileID, kind)
}

func (s *taskService) queueArchiveImport(c *gin.Context) {
	taskID, fileID := c.Param("taskID"), c.Param("fileID")
	var detected sql.NullString
	if err := s.db.QueryRowContext(c, `SELECT detected_format FROM file_nodes
        WHERE id = ? AND task_id = ? AND node_kind = 'file'`, fileID, taskID).Scan(&detected); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "file_not_found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "file_query_failed"})
		}
		return
	}
	if !archiveImportSupported(detected.String) {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "archive_import_not_supported"})
		return
	}
	s.queueManualRun(c, taskID, "file_node", fileID, job.KindArchiveImport)
}

func (s *taskService) queueImageScan(c *gin.Context) {
	taskID, fileID := c.Param("taskID"), c.Param("fileID")
	var detected string
	if err := s.db.QueryRowContext(c, `SELECT f.detected_format FROM file_nodes f
		JOIN tasks t ON t.id = f.task_id AND t.deleted_at IS NULL
		WHERE f.id = ? AND f.task_id = ? AND f.node_kind = 'file'`, fileID, taskID).Scan(&detected); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "file_not_found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "file_query_failed"})
		}
		return
	}
	if detected != "docker-tar" && detected != "oci-tar" {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "image_scan_not_supported"})
		return
	}
	idempotencyKey := strings.TrimSpace(c.GetHeader("Idempotency-Key"))
	if idempotencyKey == "" || len(idempotencyKey) > 128 || strings.ContainsRune(idempotencyKey, '\x00') {
		c.JSON(http.StatusBadRequest, gin.H{"error": "idempotency_key_required"})
		return
	}
	request, _ := json.Marshal(map[string]string{"source": "manual", "inputFormat": detected})
	run, created, err := s.enqueueRun(c, mustCurrentUser(c).ID, taskID, "file_node", fileID,
		job.KindTrivyScan, idempotencyKey, request)
	if err != nil {
		slog.Error("queue image scan failed", "request_id", c.GetString("requestID"), "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "run_creation_failed"})
		return
	}
	var jobID uint64
	var status string
	if err := s.db.QueryRowContext(c, `SELECT id, status FROM jobs WHERE run_id = ?`, run.ID).Scan(&jobID, &status); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "run_creation_failed"})
		return
	}
	responseStatus := http.StatusOK
	if created {
		responseStatus = http.StatusCreated
	}
	c.JSON(responseStatus, gin.H{"job_id": strconv.FormatUint(jobID, 10), "task_id": taskID,
		"file_node_id": fileID, "status": status, "created_at": run.CreatedAt})
}

func (s *taskService) queueCheck(c *gin.Context) {
	taskID, projectID := c.Param("taskID"), c.Param("projectID")
	var language, quality string
	if err := s.db.QueryRowContext(c, `SELECT language, result_quality FROM source_projects
        WHERE id = ? AND task_id = ? AND state = 'ready'`, projectID, taskID).Scan(&language, &quality); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "source_project_not_found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "project_query_failed"})
		}
		return
	}
	if quality == "bytecode_only" {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "source_required"})
		return
	}
	kinds := map[string]job.Kind{"c": job.KindCCheck, "java": job.KindJavaCheck, "python": job.KindPythonCheck}
	kind, ok := kinds[language]
	if !ok {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "checker_not_supported"})
		return
	}
	s.queueManualRun(c, taskID, "source_project", projectID, kind)
}

func (s *taskService) queueManualRun(c *gin.Context, taskID, subjectType, subjectID string, kind job.Kind) {
	idempotencyKey := strings.TrimSpace(c.GetHeader("Idempotency-Key"))
	if idempotencyKey == "" || len(idempotencyKey) > 128 || strings.ContainsRune(idempotencyKey, '\x00') {
		c.JSON(http.StatusBadRequest, gin.H{"error": "idempotency_key_required"})
		return
	}
	request, _ := json.Marshal(map[string]string{"source": "manual"})
	run, created, err := s.enqueueRun(c, mustCurrentUser(c).ID, taskID, subjectType, subjectID, kind, idempotencyKey, request)
	if err != nil {
		slog.Error("queue manual run failed", "request_id", c.GetString("requestID"), "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "run_creation_failed"})
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	c.JSON(status, gin.H{"run": run})
}

func (s *taskService) enqueueRun(
	ctx *gin.Context,
	userID uint64,
	taskID, subjectType, subjectID string,
	kind job.Kind,
	idempotencyKey string,
	request []byte,
) (queuedRun, bool, error) {
	runID, err := identity.UUID()
	if err != nil {
		return queuedRun{}, false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return queuedRun{}, false, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO runs
        (id, kind, status, task_id, subject_type, subject_id, created_by, idempotency_key, request)
        VALUES (?, ?, 'queued', ?, ?, ?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE id = id`, runID, kind, taskID, subjectType, subjectID, userID, idempotencyKey, request); err != nil {
		return queuedRun{}, false, err
	}
	var actual queuedRun
	if err := tx.QueryRowContext(ctx, `SELECT id, kind, status, created_at FROM runs
        WHERE created_by = ? AND kind = ? AND subject_id = ? AND idempotency_key = ? FOR UPDATE`,
		userID, kind, subjectID, idempotencyKey).Scan(&actual.ID, &actual.Kind, &actual.Status, &actual.CreatedAt); err != nil {
		return queuedRun{}, false, err
	}
	created := actual.ID == runID
	if created {
		maxAttempts := 3
		if kind == job.KindCCheck || kind == job.KindJavaCheck || kind == job.KindPythonCheck {
			maxAttempts = 2880
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO jobs (run_id, kind, status, max_attempts)
			VALUES (?, ?, 'queued', ?)`, runID, kind, maxAttempts); err != nil {
			return queuedRun{}, false, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO task_events
            (task_id, event_type, message) VALUES (?, 'run.queued', ?)`,
			taskID, fmt.Sprintf("%s 已排队", kind)); err != nil {
			return queuedRun{}, false, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO audit_logs
            (actor_user_id, action, object_type, object_id, request_id, client_ip, outcome, details)
            VALUES (?, 'run.create', 'run', ?, ?, ?, 'success', JSON_OBJECT('kind', ?, 'subjectType', ?, 'subjectId', ?))`,
			userID, runID, ctx.GetString("requestID"), ctx.ClientIP(), kind, subjectType, subjectID); err != nil {
			return queuedRun{}, false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return queuedRun{}, false, err
	}
	return actual, created, nil
}

func (s *taskService) queryFiles(ctx *gin.Context, taskID string) ([]gin.H, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT f.id, f.parent_id, f.logical_path, f.node_kind,
		f.detected_format, f.size_bytes, HEX(b.sha256)
		FROM file_nodes f LEFT JOIN blobs b ON b.id = f.blob_id
		WHERE f.task_id = ? ORDER BY f.logical_path, f.id LIMIT 20000`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]gin.H, 0)
	for rows.Next() {
		var id, logicalPath, nodeKind string
		var parent, detected, digest sql.NullString
		var size uint64
		if err := rows.Scan(&id, &parent, &logicalPath, &nodeKind, &detected, &size, &digest); err != nil {
			return nil, err
		}
		result = append(result, gin.H{"id": id, "parentId": nullableString(parent), "path": logicalPath,
			"kind": nodeKind, "detectedFormat": nullableString(detected), "sizeBytes": size,
			"sha256": strings.ToLower(digest.String)})
	}
	return result, rows.Err()
}

func (s *taskService) queryRuns(ctx *gin.Context, taskID string) ([]gin.H, error) {
	rows, err := s.db.QueryContext(ctx, taskRunsQuery, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]gin.H, 0)
	for rows.Next() {
		run, err := scanTaskRun(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, run)
	}
	return result, rows.Err()
}

func scanTaskRun(row taskRunRowScanner) (gin.H, error) {
	var id, kind, status, subjectType, subjectID string
	var quality, toolName, toolVersion, rulesetVersion, errorCode, errorMessage sql.NullString
	var created time.Time
	var started, completed sql.NullTime
	if err := row.Scan(&id, &kind, &status, &subjectType, &subjectID, &quality, &toolName,
		&toolVersion, &rulesetVersion, &errorCode, &errorMessage, &created, &started, &completed); err != nil {
		return nil, err
	}
	return gin.H{"id": id, "kind": kind, "status": status,
		"subjectType": subjectType, "subjectId": subjectID, "resultQuality": nullableString(quality),
		"toolName": nullableString(toolName), "toolVersion": nullableString(toolVersion),
		"rulesetVersion": nullableString(rulesetVersion), "errorCode": nullableString(errorCode),
		"errorMessage": nullableString(errorMessage), "createdAt": created,
		"startedAt": nullableTime(started), "completedAt": nullableTime(completed)}, nil
}

func (s *taskService) queryProjects(ctx *gin.Context, taskID string) ([]gin.H, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, file_node_id, run_id, source_kind, language,
        result_quality, file_count, size_bytes, created_at FROM source_projects
        WHERE task_id = ? AND state = 'ready' ORDER BY created_at DESC LIMIT 100`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]gin.H, 0)
	for rows.Next() {
		var id, fileID, runID, sourceKind, language, quality string
		var fileCount uint32
		var size uint64
		var created time.Time
		if err := rows.Scan(&id, &fileID, &runID, &sourceKind, &language, &quality, &fileCount, &size, &created); err != nil {
			return nil, err
		}
		result = append(result, gin.H{"id": id, "fileId": fileID, "runId": runID, "sourceKind": sourceKind,
			"language": language, "resultQuality": quality, "fileCount": fileCount, "sizeBytes": size, "createdAt": created})
	}
	return result, rows.Err()
}

func cleanUploadName(value string) (string, error) {
	value = path.Base(strings.ReplaceAll(strings.TrimSpace(value), "\\", "/"))
	if value == "" || value == "." || value == ".." || !utf8.ValidString(value) || len(value) > 512 || strings.ContainsRune(value, '\x00') {
		return "", fmt.Errorf("invalid upload filename")
	}
	return value, nil
}

func decompileKind(format string) (job.Kind, bool) {
	switch format {
	case "pe32", "pe32+", "elf32", "elf64", "macho-thin", "macho-fat", "pe", "elf", "mach-o", "macho":
		return job.KindNativeDecompile, true
	case "java-class", "class", "jar", "war", "ear", "dex", "apk":
		return job.KindJVMDecompile, true
	case "pyc":
		return job.KindPYCDecompile, true
	default:
		return "", false
	}
}

func archiveImportSupported(format string) bool {
	switch format {
	case "zip", "7z", "rar", "tar", "gzip", "xz", "deb", "rpm":
		return true
	default:
		return false
	}
}

func nullableString(value sql.NullString) any {
	if !value.Valid {
		return nil
	}
	return value.String
}

func nullableTime(value sql.NullTime) any {
	if !value.Valid {
		return nil
	}
	return value.Time
}

func nullableInt(value sql.NullInt64) any {
	if !value.Valid {
		return nil
	}
	return value.Int64
}

func requireOperator() gin.HandlerFunc {
	return func(c *gin.Context) {
		user := mustCurrentUser(c)
		if user.Role != "operator" && user.Role != "administrator" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "operation_not_allowed"})
			return
		}
		c.Next()
	}
}
