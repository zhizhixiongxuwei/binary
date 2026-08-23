package app

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type taskEventRecord struct {
	Sequence              uint64         `json:"sequence"`
	Type                  string         `json:"type"`
	Stage                 any            `json:"stage"`
	Progress              any            `json:"progress"`
	ProgressIndeterminate bool           `json:"progress_indeterminate"`
	Severity              string         `json:"severity"`
	Message               any            `json:"message"`
	Payload               map[string]any `json:"payload"`
	CreatedAt             time.Time      `json:"created_at"`
}

func (s *taskService) events(c *gin.Context) {
	taskID := c.Param("taskID")
	var exists int
	if err := s.db.QueryRowContext(c, `SELECT 1 FROM tasks WHERE id = ? AND deleted_at IS NULL`, taskID).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "task_not_found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "task_event_query_failed"})
		}
		return
	}

	lastID := uint64(0)
	if raw := strings.TrimSpace(c.GetHeader("Last-Event-ID")); raw != "" {
		if value, err := strconv.ParseUint(raw, 10, 64); err == nil {
			lastID = value
		}
	}

	c.Header("Content-Type", "text/event-stream; charset=utf-8")
	c.Header("Cache-Control", "no-cache, no-transform")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no")
	c.Status(http.StatusOK)
	c.Writer.WriteString("retry: 1000\n\n")
	c.Writer.Flush()

	poll := time.NewTicker(time.Second)
	heartbeat := time.NewTicker(15 * time.Second)
	defer poll.Stop()
	defer heartbeat.Stop()

	for {
		nextID, err := s.writeTaskEvents(c, taskID, lastID)
		if err != nil {
			return
		}
		lastID = nextID
		select {
		case <-c.Request.Context().Done():
			return
		case <-poll.C:
		case <-heartbeat.C:
			if _, err := c.Writer.WriteString(": heartbeat\n\n"); err != nil {
				return
			}
			c.Writer.Flush()
		}
	}
}

func (s *taskService) writeTaskEvents(c *gin.Context, taskID string, afterID uint64) (uint64, error) {
	rows, err := s.db.QueryContext(c, `SELECT id, event_type, message, progress_current, progress_total, created_at
		FROM task_events WHERE task_id = ? AND id > ? ORDER BY id LIMIT 200`, taskID, afterID)
	if err != nil {
		return afterID, err
	}
	defer rows.Close()

	lastID := afterID
	for rows.Next() {
		var id uint64
		var eventType string
		var message sql.NullString
		var current, total sql.NullInt64
		var created time.Time
		if err := rows.Scan(&id, &eventType, &message, &current, &total, &created); err != nil {
			return lastID, err
		}
		progress, indeterminate := eventProgress(current, total)
		normalizedType, payload := normalizeTaskEvent(eventType, message.String)
		record := taskEventRecord{
			Sequence: id, Type: normalizedType, Stage: eventStage(eventType), Progress: progress,
			ProgressIndeterminate: indeterminate, Severity: eventSeverity(eventType),
			Message: nullableString(message), Payload: payload, CreatedAt: created,
		}
		body, err := json.Marshal(record)
		if err != nil {
			return lastID, err
		}
		if _, err := fmt.Fprintf(c.Writer, "id: %d\nevent: task\ndata: %s\n\n", id, body); err != nil {
			return lastID, err
		}
		lastID = id
	}
	if err := rows.Err(); err != nil {
		return lastID, err
	}
	c.Writer.Flush()
	return lastID, nil
}

func normalizeTaskEvent(eventType, message string) (string, map[string]any) {
	payload := map[string]any{}
	switch eventType {
	case "upload.complete":
		return "task.created", payload
	case "scan.detected":
		return "task.metadata_changed", payload
	case "trivy.complete":
		payload["analyzer"] = "trivy"
		payload["phase"] = "completed"
		payload["current"] = 1
		payload["total"] = 1
		payload["finding_count"] = firstMessageNumber(message)
		return "trivy.completed", payload
	case "decompile.complete":
		payload["analyzer"] = decompileAnalyzer(message)
		payload["phase"] = "completed"
		count := firstMessageNumber(message)
		payload["current"] = count
		payload["total"] = count
		payload["completeness"] = "complete"
		return "decompile.completed", payload
	case "run.queued":
		if strings.Contains(message, "decompile") {
			payload["analyzer"] = decompileAnalyzer(message)
			payload["phase"] = "queued"
			return "decompile.queued", payload
		}
		return "task.status_changed", payload
	case "task.deleted":
		return "task.status_changed", payload
	default:
		return "task.status_changed", payload
	}
}

func decompileAnalyzer(message string) string {
	switch {
	case strings.Contains(message, "native"):
		return "ghidra"
	case strings.Contains(message, "pyc"):
		return "python-bytecode"
	default:
		return "vineflower"
	}
}

func firstMessageNumber(message string) int64 {
	for _, field := range strings.Fields(message) {
		trimmed := strings.Trim(field, "，,。.;:条个")
		if value, err := strconv.ParseInt(trimmed, 10, 64); err == nil && value >= 0 && value <= 10_000_000 {
			return value
		}
	}
	return 0
}

func eventProgress(current, total sql.NullInt64) (any, bool) {
	if !current.Valid || !total.Valid || total.Int64 <= 0 {
		return nil, true
	}
	value := float64(current.Int64) * 100 / float64(total.Int64)
	if value < 0 {
		value = 0
	}
	if value > 100 {
		value = 100
	}
	return value, false
}

func eventStage(eventType string) any {
	switch {
	case strings.HasPrefix(eventType, "upload"):
		return "VALIDATING"
	case strings.HasPrefix(eventType, "archive"):
		return "EXTRACTING"
	case strings.HasPrefix(eventType, "report"):
		return "REPORTING"
	case strings.HasPrefix(eventType, "scan"):
		return "IDENTIFYING"
	case strings.HasPrefix(eventType, "trivy"), strings.HasPrefix(eventType, "run"), strings.HasPrefix(eventType, "decompile"), strings.HasPrefix(eventType, "check"):
		return "SCANNING"
	default:
		return nil
	}
}

func eventSeverity(eventType string) string {
	if strings.Contains(eventType, "failed") || strings.Contains(eventType, "error") {
		return "error"
	}
	if strings.Contains(eventType, "partial") || strings.Contains(eventType, "warning") {
		return "warning"
	}
	return "info"
}
