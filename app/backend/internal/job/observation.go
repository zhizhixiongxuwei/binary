package job

import (
	"context"
	"database/sql"
	"errors"
)

// RecordObservation writes diagnostic/progress information without waiting on
// a publication's job lock. READ COMMITTED prevents INSERT...SELECT from taking
// shared source-table locks; NOWAIT keeps observations out of the publisher's
// lock order and its heartbeat path. A skipped observation has no side effects.
func (r *Repository) RecordObservation(ctx context.Context, claim Claim, eventType, message string, current, total any, unpublishedOnly bool) error {
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var valid int
	err = tx.QueryRowContext(ctx, `SELECT 1 FROM jobs WHERE id = ? AND run_id = ?
		AND fencing_token = ? AND status = 'running' AND lease_until > UTC_TIMESTAMP(6)
		FOR SHARE NOWAIT`, claim.ID, claim.RunID, claim.FencingToken).Scan(&valid)
	if isNowaitConflict(err) || errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	query := `INSERT INTO task_events (task_id, event_type, message, progress_current, progress_total)
		SELECT r.task_id, ?, ?, ?, ? FROM runs r JOIN tasks t ON t.id = r.task_id
		WHERE r.id = ? AND t.deleted_at IS NULL AND t.status NOT IN ('deleting', 'deleted')`
	if unpublishedOnly {
		query += ` AND r.published_at IS NULL`
	}
	if _, err := tx.ExecContext(ctx, query, eventType, message, current, total, claim.RunID); err != nil {
		return err
	}
	return tx.Commit()
}
