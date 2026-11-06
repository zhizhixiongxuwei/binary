package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/gin-gonic/gin"
)

// Only fixed route patterns and explicit identifiers are logged. Request URL
// queries, headers, bodies, cookies, model prompts and provider errors are not.
func requestObservability(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		started := time.Now()
		c.Next()
		route := c.FullPath()
		if route == "" {
			route = "unmatched"
		}
		status := c.Writer.Status()
		actor, authenticated := c.Get("currentUser")
		user, _ := actor.(currentUser)
		if (route != "/healthz" && route != "/readyz") || status >= 400 {
			slog.Info("http request completed", "request_id", c.GetString("requestID"), "method", c.Request.Method,
				"route", route, "status", status, "duration_ms", time.Since(started).Milliseconds(), "client_ip", c.ClientIP(),
				"actor_id", user.PublicID, "response_bytes", c.Writer.Size())
		}
		action, objectType, objectID, auditSuccess := auditRequestOperation(c)
		if value := c.GetString("auditObjectID"); value != "" {
			objectID = value
		}
		if action == "" || c.GetBool(adminAuditRecorded) || (status < 400 && !auditSuccess && c.GetString("auditOutcome") == "") {
			return
		}
		outcome := "success"
		if status >= 500 {
			outcome = "failure"
		} else if status >= 400 {
			outcome = "denied"
		}
		if value := c.GetString("auditOutcome"); value == "failure" || value == "denied" {
			outcome = value
		}
		var actorID any
		if authenticated && user.ID > 0 {
			actorID = user.ID
		}
		details := map[string]any{"method": c.Request.Method, "route": route, "status": status}
		if action == "audit.export" && status < 400 {
			if value, ok := c.Get("auditExportRows"); ok {
				details["rows"] = value
			}
			if value, ok := c.Get("auditExportUpperID"); ok {
				details["snapshotUpperId"] = value
			}
		}
		encoded, _ := json.Marshal(details)
		// Client disconnects must not discard security events; background lifetime is
		// bounded independently and no request/body data is retained.
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if _, err := db.ExecContext(ctx, `INSERT INTO audit_logs (actor_user_id, action, object_type, object_id, request_id, client_ip, outcome, details)
   VALUES (?, ?, ?, NULLIF(?, ''), ?, ?, ?, ?)`, actorID, action, objectType, truncateString(objectID, 64), c.GetString("requestID"), c.ClientIP(), outcome, encoded); err != nil {
			slog.Error("request audit write failed", "request_id", c.GetString("requestID"), "action", action)
		}
	}
}

func safeRecovery() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if recover() != nil {
				c.Set("auditOutcome", "failure")
				// Record the code stack, not the recovered value or a dump of headers.
				slog.Error("http request panic", "request_id", c.GetString("requestID"), "method", c.Request.Method, "route", c.FullPath(), "stack", string(debug.Stack()))
				if !c.Writer.Written() {
					c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
				} else {
					c.Abort()
				}
			}
		}()
		c.Next()
	}
}

func auditRequestOperation(c *gin.Context) (action, objectType, objectID string, success bool) {
	key := c.Request.Method + " " + c.FullPath()
	switch key {
	case "POST /api/v1/auth/login":
		return "auth.login", "user", "", true
	case "POST /api/v1/auth/logout":
		return "auth.logout", "user", "", true
	case "POST /api/v1/auth/password":
		return "auth.password.change", "user", "", true
	case "POST /api/v1/admin/users":
		return "admin.user.create", "user", "", false
	case "PATCH /api/v1/admin/users/:userID":
		return "admin.user.update", "user", c.Param("userID"), false
	case "GET /api/v1/admin/audit/export":
		return "audit.export", "audit", "", true
	case "PUT /api/v1/admin/llm/settings":
		return "llm.settings.update", "llm_settings", "", true
	case "POST /api/v1/admin/llm/test":
		return "llm.connection.test", "llm_settings", "", true
	case "POST /api/v1/uploads":
		return "upload.create", "upload", "", true
	case "PUT /api/v1/uploads/:uploadID/parts/:partNumber":
		return "upload.part.write", "upload", c.Param("uploadID"), false
	case "POST /api/v1/uploads/:uploadID/complete":
		return "upload.complete", "upload", c.Param("uploadID"), false
	case "POST /api/v1/uploads/:uploadID/tasks":
		return "task.create", "upload", c.Param("uploadID"), false
	case "DELETE /api/v1/uploads/:uploadID":
		return "upload.delete", "upload", c.Param("uploadID"), true
	case "POST /api/v1/tasks":
		return "task.create", "task", "", false
	case "DELETE /api/v1/tasks/:taskID":
		return "task.delete", "task", c.Param("taskID"), false
	case "DELETE /api/v1/tasks/:taskID/archive-source":
		return "archive.source.cleanup", "task", c.Param("taskID"), false
	case "POST /api/v1/tasks/:taskID/files/:fileID/archive-import", "POST /api/v1/tasks/:taskID/files/:fileID/image-scan", "POST /api/v1/tasks/:taskID/files/:fileID/decompile", "POST /api/v1/tasks/:taskID/projects/:projectID/check":
		return "run.create", "task", c.Param("taskID"), false
	case "POST /api/v1/tasks/:taskID/reports":
		return "report.create", "task", c.Param("taskID"), false
	case "POST /api/v1/archive-imports/:importID/task-batches":
		return "archive.task.create", "archive_import", c.Param("importID"), false
	case "POST /api/v1/archive-imports/:importID/report-bundles":
		return "archive.report_bundle.create", "archive_import", c.Param("importID"), false
	case "GET /api/v1/reports/:reportID/content":
		return "report.download", "report", c.Param("reportID"), true
	case "GET /api/v1/archive-report-bundles/:bundleID/content":
		return "archive.report_bundle.download", "archive_report_bundle", c.Param("bundleID"), true
	case "GET /api/v1/tasks/:taskID/projects/:projectID/content", "GET /api/v1/tasks/:taskID/sources":
		return "source.download", "task", c.Param("taskID"), true
	case "POST /api/v1/tasks/:taskID/projects/:projectID/files/:fileID/explanations":
		return "llm.explanation.create", "source_project", c.Param("projectID"), true
	case "POST /api/v1/tasks/:taskID/projects/:projectID/insights":
		return "llm.insight.create", "source_project", c.Param("projectID"), true
	default:
		return "", "", "", false
	}
}
