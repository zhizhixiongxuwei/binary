package app

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"os"
	"path/filepath"
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
	ID        string    `json:"id"`
	TaskID    string    `json:"taskId"`
	Format    string    `json:"format"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"createdAt"`
}

func (s *taskService) createReport(c *gin.Context) {
	var request reportRequest
	if err := c.ShouldBindJSON(&request); err != nil || (request.Format != "json" && request.Format != "html") || len(request.RunIDs) == 0 || len(request.RunIDs) > 100 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_report_request"})
		return
	}
	seen := make(map[string]struct{}, len(request.RunIDs))
	for _, runID := range request.RunIDs {
		if _, exists := seen[runID]; runID == "" || len(runID) > 64 || exists {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_report_runs"})
			return
		}
		seen[runID] = struct{}{}
	}
	taskID := c.Param("taskID")
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
		reportBody = []byte("<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\"><title>BinaryScan 报告</title>" +
			"<style>body{font:14px/1.6 system-ui;margin:32px;color:#17212b}pre{white-space:pre-wrap;background:#f5f7fa;padding:20px;border-radius:8px}</style>" +
			"</head><body><h1>BinaryScan 分析报告</h1><pre>" + html.EscapeString(string(snapshotBody)) + "</pre></body></html>")
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
	selected, _ := json.Marshal(request.RunIDs)
	user := mustCurrentUser(c)
	tx, err := s.db.BeginTx(c, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "report_creation_failed"})
		return
	}
	defer tx.Rollback()
	storageKey := filepath.ToSlash(filepath.Join("reports", relative))
	if _, err := tx.ExecContext(c, `INSERT INTO reports
        (id, task_id, created_by, format, status, storage_key, selected_run_ids, snapshot)
        VALUES (?, ?, ?, ?, 'ready', ?, ?, ?)`,
		reportID, taskID, user.ID, request.Format, storageKey, selected, snapshotBody); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "report_creation_failed"})
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": "report_creation_failed"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"report": reportRecord{
		ID: reportID, TaskID: taskID, Format: request.Format, Status: "ready", CreatedAt: time.Now().UTC(),
	}})
}

var errMutableReportRun = errors.New("report run is not in a terminal state")

func (s *taskService) buildReportSnapshot(ctx *gin.Context, taskID string, runIDs []string) (map[string]any, error) {
	var displayName, taskStatus string
	var detected sql.NullString
	var taskCreated time.Time
	if err := s.db.QueryRowContext(ctx, `SELECT display_name, status, detected_format, created_at
        FROM tasks WHERE id = ? AND deleted_at IS NULL`, taskID).Scan(&displayName, &taskStatus, &detected, &taskCreated); err != nil {
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
	findingRows, err := s.db.QueryContext(ctx, `SELECT run_id, finding_type, language, severity, rule_id,
        cwe, external_id, logical_path, start_line, start_column, title, message, details
        FROM findings WHERE run_id IN (`+placeholders+`)
        ORDER BY FIELD(severity, 'critical', 'high', 'medium', 'low', 'info'), id LIMIT 50000`, findingArgs...)
	if err != nil {
		return nil, err
	}
	findings := make([]map[string]any, 0)
	for findingRows.Next() {
		var runID, findingType, severity, title, message string
		var language, ruleID, cwe, externalID, logicalPath sql.NullString
		var line, column sql.NullInt64
		var details []byte
		if err := findingRows.Scan(&runID, &findingType, &language, &severity, &ruleID, &cwe,
			&externalID, &logicalPath, &line, &column, &title, &message, &details); err != nil {
			findingRows.Close()
			return nil, err
		}
		var evidence any
		_ = json.Unmarshal(details, &evidence)
		findings = append(findings, map[string]any{"runId": runID, "type": findingType,
			"language": nullableString(language), "severity": severity, "ruleId": nullableString(ruleID),
			"cwe": nullableString(cwe), "externalId": nullableString(externalID), "path": nullableString(logicalPath),
			"line": nullableInt(line), "column": nullableInt(column), "title": title, "message": message, "evidence": evidence})
	}
	if err := findingRows.Close(); err != nil {
		return nil, err
	}
	return map[string]any{
		"schema": "binaryscan-report-v1", "generatedAt": time.Now().UTC(),
		"task": map[string]any{"id": taskID, "displayName": displayName, "status": taskStatus,
			"detectedFormat": nullableString(detected), "createdAt": taskCreated},
		"runs": runs, "findings": findings,
	}, nil
}

func (s *taskService) listReports(c *gin.Context) {
	rows, err := s.db.QueryContext(c, `SELECT id, task_id, format, status, created_at
        FROM reports WHERE task_id = ? AND deleted_at IS NULL ORDER BY created_at DESC LIMIT 100`, c.Param("taskID"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "report_query_failed"})
		return
	}
	defer rows.Close()
	reports := make([]reportRecord, 0)
	for rows.Next() {
		var report reportRecord
		if err := rows.Scan(&report.ID, &report.TaskID, &report.Format, &report.Status, &report.CreatedAt); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "report_query_failed"})
			return
		}
		reports = append(reports, report)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "report_query_failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"reports": reports})
}

func (s *taskService) downloadReport(c *gin.Context) {
	var storageKey, format string
	if err := s.db.QueryRowContext(c, `SELECT storage_key, format FROM reports
        WHERE id = ? AND status = 'ready' AND deleted_at IS NULL`, c.Param("reportID")).Scan(&storageKey, &format); err != nil {
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
	info, err := os.Lstat(filename)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "report_file_not_found"})
		return
	}
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"binaryscan-%s.%s\"", c.Param("reportID"), format))
	if format == "html" {
		c.Header("Content-Type", "text/html; charset=utf-8")
	} else {
		c.Header("Content-Type", "application/json")
	}
	c.File(filename)
}

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
		return "", 0, err
	}
	return filepath.ToSlash(relative), int64(len(body)), nil
}
