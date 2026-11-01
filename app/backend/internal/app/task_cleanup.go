package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path"
	"time"

	"binaryscan.local/backend/internal/storage"

	"github.com/gin-gonic/gin"
)

// Deletion and its durable cleanup request commit together. Hide the task at
// once; the worker finishes physical cleanup independently of the HTTP request.
func (s *taskService) delete(c *gin.Context) {
	taskID, user := c.Param("taskID"), mustCurrentUser(c)
	tx, err := s.db.BeginTx(c, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "task_deletion_failed"})
		return
	}
	defer tx.Rollback()
	var creator uint64
	var name string
	if err := tx.QueryRowContext(c, `SELECT created_by, display_name FROM tasks
		WHERE id = ? AND deleted_at IS NULL FOR UPDATE`, taskID).Scan(&creator, &name); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "task_not_found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "task_deletion_failed"})
		}
		return
	}
	if user.Role != "administrator" && (user.Role != "operator" || user.ID != creator) {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}
	for _, query := range []string{
		`UPDATE tasks SET status = 'deleting', deleted_at = UTC_TIMESTAMP(6) WHERE id = ?`,
		`INSERT IGNORE INTO task_cleanup_queue (kind, target) VALUES ('task', ?)`,
	} {
		if _, err := tx.ExecContext(c, query, taskID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "task_deletion_failed"})
			return
		}
	}
	if _, err := tx.ExecContext(c, `INSERT INTO audit_logs
		(actor_user_id, action, object_type, object_id, request_id, client_ip, outcome, details)
		VALUES (?, 'task.delete', 'task', ?, ?, ?, 'success', JSON_OBJECT('name', ?))`,
		user.ID, taskID, c.GetString("requestID"), c.ClientIP(), name); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "task_deletion_failed"})
		return
	}
	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "task_deletion_failed"})
		return
	}
	select {
	case s.cleanupWake <- struct{}{}:
	default:
	}
	c.Status(http.StatusNoContent)
}

// CleanupDeletedTasks retries persisted work on startup and periodically. Each
// item is independent so a busy upload or an unreadable directory cannot block
// all other deletions. Nothing scans or deletes unrelated user data.
func (s *Server) CleanupDeletedTasks(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		if err := s.tasks.cleanupDeletedTasks(ctx); err != nil && ctx.Err() == nil {
			slog.Error("task cleanup failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-s.tasks.cleanupWake:
		}
	}
}

func (s *taskService) cleanupDeletedTasks(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT id, kind, target FROM task_cleanup_queue
		ORDER BY kind DESC, id LIMIT 100`)
	if err != nil {
		return err
	}
	type entry struct {
		id           uint64
		kind, target string
	}
	var entries []entry
	for rows.Next() {
		var item entry
		if err := rows.Scan(&item.id, &item.kind, &item.target); err != nil {
			rows.Close()
			return err
		}
		entries = append(entries, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, item := range entries {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		itemCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := s.cleanupEntry(itemCtx, item.id, item.kind, item.target)
		cancel()
		if err != nil {
			slog.Warn("task cleanup will retry", "kind", item.kind, "target", item.target, "error", err)
		}
	}
	return nil
}

func (s *taskService) cleanupEntry(ctx context.Context, id uint64, kind, target string) error {
	if kind == "task" || kind == "blob" {
		lockCtx, cancel := context.WithTimeout(ctx, time.Second)
		unlock, err := s.blobs.LockPublication(lockCtx, true)
		cancel()
		if err != nil {
			return err
		}
		defer unlock()
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT 1 FROM task_cleanup_queue WHERE id = ?
		FOR UPDATE SKIP LOCKED`, id).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}
	switch kind {
	case "task":
		err = s.purgeTask(ctx, tx, target)
	case "path":
		err = storage.RemoveTree(s.storageRoot, target)
	case "blob":
		err = s.purgeUnusedBlob(ctx, tx, target)
	default:
		err = fmt.Errorf("unknown cleanup kind %q", kind)
	}
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM task_cleanup_queue WHERE id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// The exclusive publication lock lets an in-flight archive register its blobs
// before we collect them. Fencing/deleting jobs then prevents late workers from
// publishing results after this transaction; FK cascades remove their records.
func (s *taskService) purgeTask(ctx context.Context, tx *sql.Tx, taskID string) error {
	var uploadID sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT upload_id FROM tasks
		WHERE id = ? AND deleted_at IS NOT NULL FOR UPDATE`, taskID).Scan(&uploadID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}
	if uploadID.Valid {
		var locked string
		if err := tx.QueryRowContext(ctx, `SELECT id FROM uploads WHERE id = ? FOR UPDATE`, uploadID.String).Scan(&locked); err != nil {
			return err
		}
	}
	queries := []string{
		`UPDATE jobs j JOIN runs r ON r.id = j.run_id
		 SET j.status = 'cancelled', j.fencing_token = j.fencing_token + 1,
		 j.cancel_requested_at = UTC_TIMESTAMP(6), j.lease_until = NULL WHERE r.task_id = ?`,
		`UPDATE job_attempts a JOIN jobs j ON j.id = a.job_id
		 JOIN runs r ON r.id = j.run_id SET a.status = 'cancelled',
		 a.completed_at = UTC_TIMESTAMP(6) WHERE r.task_id = ? AND a.status = 'running'`,
		`UPDATE resource_slots s JOIN jobs j ON j.id = s.job_id JOIN runs r ON r.id = j.run_id
		 SET s.job_id = NULL, s.fencing_token = NULL, s.lease_owner = NULL, s.acquired_at = NULL WHERE r.task_id = ?`,
		`INSERT IGNORE INTO task_cleanup_queue (kind, target)
		 SELECT 'blob', blob_id FROM tasks WHERE id = ?`,
		`INSERT IGNORE INTO task_cleanup_queue (kind, target)
		 SELECT 'blob', blob_id FROM file_nodes WHERE task_id = ? AND blob_id IS NOT NULL`,
		`INSERT IGNORE INTO task_cleanup_queue (kind, target)
		 SELECT 'blob', input_blob_id FROM source_projects WHERE task_id = ? AND input_blob_id IS NOT NULL`,
		`INSERT IGNORE INTO task_cleanup_queue (kind, target)
		 SELECT 'blob', e.blob_id FROM archive_entries e JOIN runs r ON r.id = e.import_run_id
		 WHERE r.task_id = ? AND e.blob_id IS NOT NULL`,
		`INSERT IGNORE INTO task_cleanup_queue (kind, target)
		 SELECT 'path', CONCAT('projects/', source_kind, '/', root_storage_key) FROM source_projects WHERE task_id = ?`,
		`INSERT IGNORE INTO task_cleanup_queue (kind, target)
		 SELECT 'path', CONCAT('reports/archive-bundles/', id) FROM runs WHERE task_id = ?`,
		`INSERT IGNORE INTO task_cleanup_queue (kind, target) VALUES ('path', CONCAT('reports/', ?))`,
		`INSERT IGNORE INTO task_cleanup_queue (kind, target) VALUES ('path', CONCAT('artifacts/', ?))`,
		// Bundles contain copies of child reports and source files. Invalidate
		// those copies as well; a fresh bundle can still include surviving tasks.
		`INSERT IGNORE INTO task_cleanup_queue (kind, target)
		 SELECT 'path', storage_key FROM archive_report_bundles
		 WHERE JSON_CONTAINS(manifest, JSON_OBJECT('task_id', ?), '$.children')`,
		`DELETE FROM archive_report_bundles
		 WHERE JSON_CONTAINS(manifest, JSON_OBJECT('task_id', ?), '$.children')`,
		// A derived child is an independent task. Detach its source entry so
		// deleting it does not delete the parent import or other children.
		`UPDATE archive_entries SET created_task_id = NULL,
		 status = IF(blob_id IS NULL, 'candidate', 'materialized') WHERE created_task_id = ?`,
		`DELETE FROM findings WHERE task_id = ?`,
		`DELETE FROM source_projects WHERE task_id = ?`,
		`DELETE FROM runs WHERE task_id = ?`,
		`DELETE FROM tasks WHERE id = ?`,
	}
	for _, query := range queries {
		if _, err := tx.ExecContext(ctx, query, taskID); err != nil {
			return fmt.Errorf("purge task data: %w", err)
		}
	}
	if uploadID.Valid {
		result, err := tx.ExecContext(ctx, `DELETE FROM uploads WHERE id = ?
			AND NOT EXISTS (SELECT 1 FROM tasks WHERE upload_id = ?)`, uploadID.String, uploadID.String)
		if err != nil {
			return err
		}
		removed, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if removed > 0 {
			if _, err := tx.ExecContext(ctx, `INSERT IGNORE INTO task_cleanup_queue (kind, target)
				VALUES ('path', ?)`, path.Join("uploads", uploadID.String)); err != nil {
				return err
			}
		}
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO audit_logs
		(action, object_type, object_id, outcome, details)
		VALUES ('task.cleanup', 'task', ?, 'success', JSON_OBJECT('filesQueued', TRUE))`, taskID)
	return err
}

func (s *taskService) purgeUnusedBlob(ctx context.Context, tx *sql.Tx, blobID string) error {
	var key string
	if err := tx.QueryRowContext(ctx, `SELECT storage_key FROM blobs WHERE id = ? FOR UPDATE`, blobID).Scan(&key); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}
	var referenced bool
	if err := tx.QueryRowContext(ctx, `SELECT
		EXISTS(SELECT 1 FROM tasks WHERE blob_id = ?) OR
		EXISTS(SELECT 1 FROM uploads WHERE blob_id = ?) OR
		EXISTS(SELECT 1 FROM file_nodes WHERE blob_id = ?) OR
		EXISTS(SELECT 1 FROM archive_entries WHERE blob_id = ?) OR
		EXISTS(SELECT 1 FROM source_projects WHERE input_blob_id = ?)`,
		blobID, blobID, blobID, blobID, blobID).Scan(&referenced); err != nil {
		return err
	}
	if referenced {
		return nil
	}
	// Remove the file while the orphan row is locked. If the DB commit fails,
	// retrying is harmless; a new ingestion holds the shared publication lock
	// and recreates the content before registering any new owner.
	if err := storage.RemoveTree(path.Join(s.storageRoot, "blobs"), key); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM blobs WHERE id = ?`, blobID)
	return err
}
