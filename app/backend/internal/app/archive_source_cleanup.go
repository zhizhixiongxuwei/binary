package app

import (
	"database/sql"
	"errors"
	"net/http"
	"path/filepath"

	"github.com/gin-gonic/gin"
)

// Source removal keeps the parent task and import history as the identity of
// the group. Ordinary task deletion purges that history and is unsuitable here.
func (s *taskService) cleanupArchiveSource(c *gin.Context) {
	taskID, user := c.Param("taskID"), mustCurrentUser(c)
	tx, err := s.db.BeginTx(c, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "archive_source_cleanup_failed"})
		return
	}
	defer tx.Rollback()
	var creator uint64
	var uploadID sql.NullString
	var deleted sql.NullTime
	var mode, name string
	err = tx.QueryRowContext(c, `SELECT created_by, upload_id, deleted_at,
	 COALESCE(analysis_mode, input_category, 'binary'), display_name FROM tasks WHERE id = ? FOR UPDATE`, taskID).
		Scan(&creator, &uploadID, &deleted, &mode, &name)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "task_not_found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "archive_source_cleanup_failed"})
		}
		return
	}
	if user.Role != "administrator" && (user.Role != "operator" || user.ID != creator) {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}
	var imports, active int
	if err := tx.QueryRowContext(c, `SELECT COALESCE(SUM(kind = 'archive_import'), 0), COALESCE(SUM(status IN ('queued', 'running')), 0)
	 FROM runs WHERE task_id = ?`, taskID).Scan(&imports, &active); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "archive_source_cleanup_failed"})
		return
	}
	if mode != "archive" && imports == 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "archive_import_not_supported"})
		return
	}
	var activeJobs int
	if err := tx.QueryRowContext(c, `SELECT COUNT(*) FROM jobs j JOIN runs r ON r.id = j.run_id
	 WHERE r.task_id = ? AND j.status IN ('queued', 'leased', 'running')`, taskID).Scan(&activeJobs); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "archive_source_cleanup_failed"})
		return
	}
	if active > 0 || activeJobs > 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "upload_invalid_state"})
		return
	}
	if deleted.Valid {
		c.Status(http.StatusNoContent)
		return
	}
	// Uncreated members can no longer be launched. Created-member links and all
	// reports remain available, including those from older import runs.
	if _, err := tx.ExecContext(c, `DELETE entry FROM archive_entries entry JOIN runs r ON r.id = entry.import_run_id
	 WHERE r.task_id = ? AND r.kind = 'archive_import' AND entry.created_task_id IS NULL`, taskID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "archive_source_cleanup_failed"})
		return
	}
	if _, err := tx.ExecContext(c, `UPDATE tasks SET status = 'deleted', deleted_at = UTC_TIMESTAMP(6) WHERE id = ?`, taskID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "archive_source_cleanup_failed"})
		return
	}
	// A unified upload can feed other analysis modes; leave their immutable
	// upload and blob references intact. Only unused upload parts are removed.
	if uploadID.Valid {
		if _, err := tx.ExecContext(c, `INSERT IGNORE INTO task_cleanup_queue (kind, target) VALUES ('path', ?)`,
			filepath.ToSlash(filepath.Join("uploads", uploadID.String, "parts"))); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "archive_source_cleanup_failed"})
			return
		}
	}
	if _, err := tx.ExecContext(c, `INSERT INTO audit_logs
	 (actor_user_id, action, object_type, object_id, request_id, client_ip, outcome, details)
	 VALUES (?, 'archive.source.cleanup', 'task', ?, ?, ?, 'success', JSON_OBJECT('name', ?))`,
		user.ID, taskID, c.GetString("requestID"), c.ClientIP(), name); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "archive_source_cleanup_failed"})
		return
	}
	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "archive_source_cleanup_failed"})
		return
	}
	c.Status(http.StatusNoContent)
}
