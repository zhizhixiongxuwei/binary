package app

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"binaryscan.local/backend/internal/identity"
	"binaryscan.local/backend/internal/storage"

	"github.com/gin-gonic/gin"
)

type reportRequest struct {
	Format string   `json:"format"`
	RunIDs []string `json:"runIds"`
}

type reportRecord struct {
	ID          string    `json:"id"`
	TaskID      string    `json:"taskId"`
	Format      string    `json:"format"`
	Schema      string    `json:"schemaVersion"`
	Status      string    `json:"status"`
	SHA256      string    `json:"sha256,omitempty"`
	SizeBytes   int64     `json:"sizeBytes,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
	CompletedAt time.Time `json:"completedAt,omitempty"`
}

// storedReport 保留响应字段之外的规范化运行集合和删除状态，用于精确比较幂等请求意图。
type storedReport struct {
	Record  reportRecord
	RunIDs  []string
	Deleted bool
}

type reportRowScanner interface {
	Scan(dest ...any) error
}

const maxReportRequestBytes = 32 << 10

// createReport 根据指定终态运行构造一次不可变快照，再渲染为 JSON、HTML 或 DOCX。
// RunIDs 先排序为规范意图；同一用户/任务/幂等键只能重放完全相同的格式与运行集合。
// 制品文件先原子发布，数据库记录后提交，任一步失败会删除本次文件；若 Commit 结果不确定，
// 则按幂等键反查数据库决定保留文件还是返回并发请求已经创建的报告。
func (s *taskService) createReport(c *gin.Context) {
	idempotencyKey := strings.TrimSpace(c.GetHeader("Idempotency-Key"))
	if !validIdempotencyKey(idempotencyKey) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "idempotency_key_required"})
		return
	}
	var request reportRequest
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxReportRequestBytes)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		(request.Format != "json" && request.Format != "html" && request.Format != "docx") ||
		len(request.RunIDs) == 0 || len(request.RunIDs) > 100 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_report_request"})
		return
	}
	seen := make(map[string]struct{}, len(request.RunIDs))
	for _, runID := range request.RunIDs {
		if _, exists := seen[runID]; !canonicalUUID(runID) || exists {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_report_runs"})
			return
		}
		seen[runID] = struct{}{}
	}
	sort.Strings(request.RunIDs)
	taskID := c.Param("taskID")
	user := mustCurrentUser(c)
	existing, found, err := s.loadReportByIdempotency(c, user.ID, taskID, idempotencyKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "report_creation_failed"})
		return
	}
	if found {
		if !reportIntentMatches(existing, request) {
			c.JSON(http.StatusConflict, gin.H{"error": "report_idempotency_conflict"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"report": existing.Record})
		return
	}
	snapshot, err := s.buildReportSnapshot(c, taskID, request.RunIDs)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "report_subject_not_found"})
		} else if errors.Is(err, errMutableReportRun) {
			c.JSON(http.StatusConflict, gin.H{"error": "report_run_not_finished"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "report_creation_failed"})
		}
		return
	}
	snapshotBody, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "report_creation_failed"})
		return
	}
	reportBody := snapshotBody
	if request.Format == "html" {
		reportBody = buildHTMLReport(snapshot)
	} else if request.Format == "docx" {
		reportBody, err = buildDOCXReport(snapshot)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "report_creation_failed"})
			return
		}
	}
	reportID, err := identity.UUID()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "report_creation_failed"})
		return
	}
	relative, sizeBytes, err := publishReportFile(s.reportRoot, taskID, reportID, request.Format, reportBody)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "report_creation_failed"})
		return
	}
	keepPublished := false
	defer func() {
		if !keepPublished {
			_ = os.Remove(filepath.Join(s.reportRoot, filepath.FromSlash(relative)))
		}
	}()
	selected, _ := json.Marshal(request.RunIDs)
	digest := sha256.Sum256(reportBody)
	tx, err := s.db.BeginTx(c, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "report_creation_failed"})
		return
	}
	defer tx.Rollback()
	storageKey := filepath.ToSlash(filepath.Join("reports", relative))
	if _, err := tx.ExecContext(c, `INSERT INTO reports
		(id, task_id, created_by, idempotency_key, format, schema_version, status, storage_key, sha256,
		 size_bytes, selected_run_ids, snapshot)
		VALUES (?, ?, ?, ?, ?, ?, 'ready', ?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE id = id`,
		reportID, taskID, user.ID, idempotencyKey, request.Format, reportSchemaVersion, storageKey,
		digest[:], sizeBytes, selected, snapshotBody); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "report_creation_failed"})
		return
	}
	actual, err := loadStoredReport(tx.QueryRowContext(c, `SELECT id, task_id, format,
		schema_version, status, HEX(sha256), size_bytes, created_at, selected_run_ids, deleted_at
		FROM reports WHERE created_by = ? AND task_id = ? AND idempotency_key = ? FOR UPDATE`,
		user.ID, taskID, idempotencyKey))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "report_creation_failed"})
		return
	}
	if actual.Record.ID != reportID {
		if !reportIntentMatches(actual, request) {
			c.JSON(http.StatusConflict, gin.H{"error": "report_idempotency_conflict"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"report": actual.Record})
		return
	}
	if _, err := tx.ExecContext(c, `INSERT INTO task_events
        (task_id, event_type, message) VALUES (?, 'report.ready', ?)`,
		taskID, fmt.Sprintf("%s 报告已生成，共 %d 字节", strings.ToUpper(request.Format), sizeBytes)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "report_creation_failed"})
		return
	}
	if _, err := tx.ExecContext(c, `INSERT INTO audit_logs
        (actor_user_id, action, object_type, object_id, request_id, client_ip, outcome, details)
        VALUES (?, 'report.create', 'report', ?, ?, ?, 'success', JSON_OBJECT('taskId', ?, 'format', ?))`,
		user.ID, reportID, c.GetString("requestID"), c.ClientIP(), taskID, request.Format); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "report_creation_failed"})
		return
	}
	if err := tx.Commit(); err != nil {
		// 连接中断不等于事务一定回滚；以唯一幂等记录回读结果，避免误删已经提交并被引用的制品。
		committed, found, queryErr := s.loadReportByIdempotency(c, user.ID, taskID, idempotencyKey)
		if queryErr == nil && found {
			if committed.Record.ID == reportID {
				keepPublished = true
				if !reportIntentMatches(committed, request) {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "report_creation_failed"})
					return
				}
				c.JSON(http.StatusCreated, gin.H{"report": committed.Record})
				return
			}
			if !reportIntentMatches(committed, request) {
				c.JSON(http.StatusConflict, gin.H{"error": "report_idempotency_conflict"})
				return
			}
			c.JSON(http.StatusOK, gin.H{"report": committed.Record})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "report_creation_failed"})
		return
	}
	keepPublished = true
	c.JSON(http.StatusCreated, gin.H{"report": actual.Record})
}

func (s *taskService) loadReportByIdempotency(
	ctx context.Context,
	userID uint64,
	taskID, idempotencyKey string,
) (storedReport, bool, error) {
	stored, err := loadStoredReport(s.db.QueryRowContext(ctx, `SELECT r.id, r.task_id, r.format,
		r.schema_version, r.status, HEX(r.sha256), r.size_bytes, r.created_at,
		r.selected_run_ids, r.deleted_at
		FROM reports r JOIN tasks t ON t.id = r.task_id AND t.deleted_at IS NULL
		WHERE r.created_by = ? AND r.task_id = ? AND r.idempotency_key = ?`,
		userID, taskID, idempotencyKey))
	if errors.Is(err, sql.ErrNoRows) {
		return storedReport{}, false, nil
	}
	return stored, err == nil, err
}

func loadStoredReport(row reportRowScanner) (storedReport, error) {
	var stored storedReport
	var sha sql.NullString
	var size sql.NullInt64
	var selected []byte
	var deleted sql.NullTime
	if err := row.Scan(&stored.Record.ID, &stored.Record.TaskID, &stored.Record.Format,
		&stored.Record.Schema, &stored.Record.Status, &sha, &size, &stored.Record.CreatedAt,
		&selected, &deleted); err != nil {
		return storedReport{}, err
	}
	if err := json.Unmarshal(selected, &stored.RunIDs); err != nil {
		return storedReport{}, fmt.Errorf("decode selected report runs: %w", err)
	}
	stored.Deleted = deleted.Valid
	stored.Record.SHA256 = strings.ToLower(sha.String)
	if size.Valid {
		stored.Record.SizeBytes = size.Int64
	}
	if stored.Record.Status == "ready" {
		stored.Record.CompletedAt = stored.Record.CreatedAt
	}
	return stored, nil
}

func reportIntentMatches(stored storedReport, request reportRequest) bool {
	if stored.Deleted || stored.Record.Format != request.Format || len(stored.RunIDs) != len(request.RunIDs) {
		return false
	}
	left := append([]string(nil), stored.RunIDs...)
	right := append([]string(nil), request.RunIDs...)
	sort.Strings(left)
	sort.Strings(right)
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

var errMutableReportRun = errors.New("report run is not in a terminal state")

// buildReportSnapshot 只接受属于同一任务的终态运行，把当时的任务元数据、运行、发现及源码摘要
// 固化进报告。发现超过 50000 条时显式标记截断，避免报告生成变成无界内存/文件操作。
func (s *taskService) buildReportSnapshot(ctx *gin.Context, taskID string, runIDs []string) (map[string]any, error) {
	var displayName, taskStatus string
	var detected sql.NullString
	var inputSHA256 string
	var taskCreated time.Time
	if err := s.db.QueryRowContext(ctx, `SELECT t.display_name, t.status, t.detected_format,
		HEX(b.sha256), t.created_at FROM tasks t JOIN blobs b ON b.id = t.blob_id
		WHERE t.id = ? AND t.deleted_at IS NULL`, taskID).Scan(
		&displayName, &taskStatus, &detected, &inputSHA256, &taskCreated,
	); err != nil {
		return nil, err
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(runIDs)), ",")
	arguments := make([]any, 0, len(runIDs)+1)
	arguments = append(arguments, taskID)
	for _, runID := range runIDs {
		arguments = append(arguments, runID)
	}
	runRows, err := s.db.QueryContext(ctx, `SELECT id, kind, status, subject_type, subject_id,
        result_quality, tool_name, tool_version, error_code, error_message, created_at, started_at, completed_at
        FROM runs WHERE task_id = ? AND id IN (`+placeholders+`) ORDER BY created_at`, arguments...)
	if err != nil {
		return nil, err
	}
	runs := make([]map[string]any, 0, len(runIDs))
	for runRows.Next() {
		var id, kind, status, subjectType, subjectID string
		var quality, toolName, toolVersion, errorCode, errorMessage sql.NullString
		var created time.Time
		var started, completed sql.NullTime
		if err := runRows.Scan(&id, &kind, &status, &subjectType, &subjectID, &quality, &toolName,
			&toolVersion, &errorCode, &errorMessage, &created, &started, &completed); err != nil {
			runRows.Close()
			return nil, err
		}
		if status == "queued" || status == "running" {
			runRows.Close()
			return nil, errMutableReportRun
		}
		runs = append(runs, map[string]any{"id": id, "kind": kind, "status": status,
			"subjectType": subjectType, "subjectId": subjectID, "resultQuality": nullableString(quality),
			"toolName": nullableString(toolName), "toolVersion": nullableString(toolVersion),
			"errorCode": nullableString(errorCode), "errorMessage": nullableString(errorMessage),
			"createdAt": created, "startedAt": nullableTime(started), "completedAt": nullableTime(completed)})
	}
	if err := runRows.Close(); err != nil {
		return nil, err
	}
	if len(runs) != len(runIDs) {
		return nil, sql.ErrNoRows
	}
	findingArgs := make([]any, len(runIDs))
	for index, runID := range runIDs {
		findingArgs[index] = runID
	}
	findingRows, err := s.db.QueryContext(ctx, `SELECT f.run_id, f.finding_type, f.language,
		f.severity, f.rule_id, f.cwe, f.external_id, f.logical_path, f.start_line,
		f.start_column, f.end_line, f.end_column, f.title, f.message, f.snippet,
		f.snippet_start_line, f.source_project_id, f.source_file_id, HEX(sf.sha256), f.details
		FROM findings f LEFT JOIN source_files sf ON sf.id = f.source_file_id
		WHERE f.run_id IN (`+placeholders+`)
		ORDER BY FIELD(f.severity, 'critical', 'high', 'medium', 'low', 'info'), f.id LIMIT 50001`, findingArgs...)
	if err != nil {
		return nil, err
	}
	findings := make([]map[string]any, 0)
	for findingRows.Next() {
		var runID, findingType, severity, title, message string
		var language, ruleID, cwe, externalID, logicalPath sql.NullString
		var snippet, sourceProjectID, sourceFileID, sourceSHA256 sql.NullString
		var line, column, endLine, endColumn, snippetStartLine sql.NullInt64
		var details []byte
		if err := findingRows.Scan(&runID, &findingType, &language, &severity, &ruleID, &cwe,
			&externalID, &logicalPath, &line, &column, &endLine, &endColumn, &title, &message,
			&snippet, &snippetStartLine, &sourceProjectID, &sourceFileID, &sourceSHA256, &details); err != nil {
			findingRows.Close()
			return nil, err
		}
		var evidence any
		_ = json.Unmarshal(details, &evidence)
		findings = append(findings, map[string]any{"runId": runID, "type": findingType,
			"language": nullableString(language), "severity": severity, "ruleId": nullableString(ruleID),
			"cwe": nullableString(cwe), "externalId": nullableString(externalID), "path": nullableString(logicalPath),
			"sourceProjectId": nullableString(sourceProjectID), "sourceFileId": nullableString(sourceFileID),
			"sourceSha256": strings.ToLower(sourceSHA256.String), "startLine": nullableInt(line),
			"startColumn": nullableInt(column), "endLine": nullableInt(endLine), "endColumn": nullableInt(endColumn),
			"snippet": nullableString(snippet), "snippetStartLine": nullableInt(snippetStartLine),
			"title": title, "message": message, "evidence": evidence})
	}
	if err := findingRows.Close(); err != nil {
		return nil, err
	}
	findingsTruncated := len(findings) > 50000
	if findingsTruncated {
		findings = findings[:50000]
	}
	return map[string]any{
		"schema": reportSchemaVersion, "generatedAt": time.Now().UTC(),
		"task": map[string]any{"id": taskID, "displayName": displayName, "status": taskStatus,
			"detectedFormat": nullableString(detected), "inputSha256": strings.ToLower(inputSHA256),
			"createdAt": taskCreated},
		"summary": buildReportSummary(runs, findings),
		"runs":    runs, "findings": findings, "findingsTruncated": findingsTruncated,
	}, nil
}

func (s *taskService) listReports(c *gin.Context) {
	rows, err := s.db.QueryContext(c, `SELECT r.id, r.task_id, r.format, r.schema_version,
		r.status, r.storage_key, HEX(r.sha256), r.size_bytes, r.created_at
		FROM reports r JOIN tasks t ON t.id = r.task_id AND t.deleted_at IS NULL
		WHERE r.task_id = ? AND r.deleted_at IS NULL ORDER BY r.created_at DESC LIMIT 100`, c.Param("taskID"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "report_query_failed"})
		return
	}
	defer rows.Close()
	reports := make([]reportRecord, 0)
	for rows.Next() {
		var report reportRecord
		var storageKey string
		var sha sql.NullString
		var size sql.NullInt64
		if err := rows.Scan(&report.ID, &report.TaskID, &report.Format, &report.Schema,
			&report.Status, &storageKey, &sha, &size, &report.CreatedAt); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "report_query_failed"})
			return
		}
		if report.Status == "ready" {
			report.CompletedAt = report.CreatedAt
			report.SHA256 = strings.ToLower(sha.String)
			report.SizeBytes = size.Int64
		}
		reports = append(reports, report)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "report_query_failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"reports": reports})
}

// downloadReport 不仅依赖数据库 ready 状态，还在每次传输前复核磁盘对象的类型、大小和 SHA-256。
// ETag 始终对应原始不可变报告；可选 gzip 只是传输编码，不改变数据库中记录的制品身份。
func (s *taskService) downloadReport(c *gin.Context) {
	encoding := c.Query("encoding")
	if encoding != "" && encoding != "identity" && encoding != "gzip" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_report_encoding"})
		return
	}
	var storageKey, format string
	var expectedSHA sql.NullString
	var expectedSize sql.NullInt64
	if err := s.db.QueryRowContext(c, `SELECT r.storage_key, r.format, HEX(r.sha256), r.size_bytes FROM reports r
		JOIN tasks t ON t.id = r.task_id AND t.deleted_at IS NULL
		WHERE r.id = ? AND r.status = 'ready' AND r.deleted_at IS NULL`, c.Param("reportID")).Scan(
		&storageKey, &format, &expectedSHA, &expectedSize); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "report_not_found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "report_query_failed"})
		}
		return
	}
	cleaned, err := storage.CleanRelativePath(storageKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "report_storage_invalid"})
		return
	}
	filename := filepath.Join(s.storageRoot, filepath.FromSlash(cleaned))
	if err := verifyReportFile(filename, expectedSize, expectedSHA); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "report_storage_corrupt"})
		return
	}
	if expectedSHA.Valid && expectedSHA.String != "" {
		c.Header("ETag", `"`+strings.ToLower(expectedSHA.String)+`"`)
	}
	if encoding == "gzip" {
		body, err := os.ReadFile(filename)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "report_file_not_found"})
			return
		}
		var compressed bytes.Buffer
		writer := gzip.NewWriter(&compressed)
		if _, err := writer.Write(body); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "report_compression_failed"})
			return
		}
		if err := writer.Close(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "report_compression_failed"})
			return
		}
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"binaryscan-%s.%s.gz\"", c.Param("reportID"), format))
		c.Data(http.StatusOK, "application/gzip", compressed.Bytes())
		return
	}
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"binaryscan-%s.%s\"", c.Param("reportID"), format))
	if format == "html" {
		c.Header("Content-Type", "text/html; charset=utf-8")
	} else if format == "docx" {
		c.Header("Content-Type", "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
	} else {
		c.Header("Content-Type", "application/json")
	}
	c.File(filename)
}

// verifyReportFile 拒绝链接和非普通文件，并以数据库中的长度/摘要作为下载前完整性锚。
func verifyReportFile(filename string, expectedSize sql.NullInt64, expectedSHA sql.NullString) error {
	info, err := os.Lstat(filename)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("report is not a regular file")
	}
	if expectedSize.Valid && info.Size() != expectedSize.Int64 {
		return fmt.Errorf("report size does not match database record")
	}
	if !expectedSHA.Valid || expectedSHA.String == "" {
		return nil
	}
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return err
	}
	if !strings.EqualFold(fmt.Sprintf("%x", hasher.Sum(nil)), expectedSHA.String) {
		return fmt.Errorf("report digest does not match database record")
	}
	return nil
}

// publishReportFile 将完整内容写入同文件系统暂存区并 fsync，再以硬链接无覆盖地发布到报告 ID 路径。
// 发布成功后设为只读；数据库登记失败时由调用方删除该文件，实现可恢复的文件/事务两阶段流程。
func publishReportFile(root, taskID, reportID, format string, body []byte) (string, int64, error) {
	for _, value := range []string{taskID, reportID} {
		if _, err := storage.CleanRelativePath(value); err != nil {
			return "", 0, err
		}
	}
	relative := filepath.Join(taskID, reportID+"."+format)
	destination := filepath.Join(root, relative)
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return "", 0, err
	}
	temporary, err := os.CreateTemp(filepath.Join(root, ".staging"), "report-*")
	if err != nil {
		return "", 0, err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if _, err := temporary.Write(body); err != nil {
		temporary.Close()
		return "", 0, err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return "", 0, err
	}
	if err := temporary.Close(); err != nil {
		return "", 0, err
	}
	if err := os.Link(temporaryName, destination); err != nil {
		return "", 0, err
	}
	if err := os.Chmod(destination, 0o440); err != nil {
		_ = os.Remove(destination)
		return "", 0, err
	}
	return filepath.ToSlash(relative), int64(len(body)), nil
}
