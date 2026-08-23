package app

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
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
	ID          string    `json:"id"`
	TaskID      string    `json:"taskId"`
	Format      string    `json:"format"`
	Status      string    `json:"status"`
	SHA256      string    `json:"sha256,omitempty"`
	SizeBytes   int64     `json:"sizeBytes,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
	CompletedAt time.Time `json:"completedAt,omitempty"`
}

func (s *taskService) createReport(c *gin.Context) {
	var request reportRequest
	if err := c.ShouldBindJSON(&request); err != nil || (request.Format != "json" && request.Format != "html" && request.Format != "docx") || len(request.RunIDs) == 0 || len(request.RunIDs) > 100 {
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
	} else if request.Format == "docx" {
		reportBody, err = buildDOCXReport(snapshotBody)
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
	digest := sha256.Sum256(reportBody)
	now := time.Now().UTC()
	c.JSON(http.StatusCreated, gin.H{"report": reportRecord{
		ID: reportID, TaskID: taskID, Format: request.Format, Status: "ready", SHA256: fmt.Sprintf("%x", digest[:]),
		SizeBytes: sizeBytes, CreatedAt: now, CompletedAt: now,
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
	rows, err := s.db.QueryContext(c, `SELECT id, task_id, format, status, storage_key, created_at
        FROM reports WHERE task_id = ? AND deleted_at IS NULL ORDER BY created_at DESC LIMIT 100`, c.Param("taskID"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "report_query_failed"})
		return
	}
	defer rows.Close()
	reports := make([]reportRecord, 0)
	for rows.Next() {
		var report reportRecord
		var storageKey string
		if err := rows.Scan(&report.ID, &report.TaskID, &report.Format, &report.Status, &storageKey, &report.CreatedAt); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "report_query_failed"})
			return
		}
		if report.Status == "ready" {
			report.CompletedAt = report.CreatedAt
			if cleaned, cleanErr := storage.CleanRelativePath(storageKey); cleanErr == nil {
				if body, readErr := os.ReadFile(filepath.Join(s.storageRoot, filepath.FromSlash(cleaned))); readErr == nil {
					digest := sha256.Sum256(body)
					report.SHA256 = fmt.Sprintf("%x", digest[:])
					report.SizeBytes = int64(len(body))
				}
			}
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
	if c.Query("encoding") == "gzip" {
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

func buildDOCXReport(snapshot []byte) ([]byte, error) {
	var body bytes.Buffer
	archive := zip.NewWriter(&body)
	files := map[string]string{
		"[Content_Types].xml": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>`,
		"_rels/.rels": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>`,
		"word/document.xml": docxDocumentXML(snapshot),
	}
	for _, name := range []string{"[Content_Types].xml", "_rels/.rels", "word/document.xml"} {
		writer, err := archive.Create(name)
		if err != nil {
			archive.Close()
			return nil, err
		}
		if _, err := writer.Write([]byte(files[name])); err != nil {
			archive.Close()
			return nil, err
		}
	}
	if err := archive.Close(); err != nil {
		return nil, err
	}
	return body.Bytes(), nil
}

func docxDocumentXML(snapshot []byte) string {
	var paragraphs strings.Builder
	paragraphs.WriteString(`<w:p><w:r><w:rPr><w:b/><w:sz w:val="32"/></w:rPr><w:t>BinaryScan 分析报告</w:t></w:r></w:p>`)
	for _, line := range strings.Split(string(snapshot), "\n") {
		paragraphs.WriteString(`<w:p><w:r><w:rPr><w:rFonts w:ascii="Courier New" w:hAnsi="Courier New"/><w:sz w:val="18"/></w:rPr><w:t xml:space="preserve">`)
		paragraphs.WriteString(html.EscapeString(line))
		paragraphs.WriteString(`</w:t></w:r></w:p>`)
	}
	return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>` +
		paragraphs.String() + `<w:sectPr><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1134" w:right="1134" w:bottom="1134" w:left="1134"/></w:sectPr></w:body></w:document>`
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
