package job

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

type Repository struct {
	db *sql.DB
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

func (r *Repository) EnsurePool(ctx context.Context, pool string, count int) error {
	if pool == "" || count < 0 {
		return fmt.Errorf("invalid resource pool definition")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin resource pool update: %w", err)
	}
	defer tx.Rollback()
	for slot := 1; slot <= count; slot++ {
		if _, err := tx.ExecContext(ctx, `INSERT INTO resource_slots (pool, slot_number, enabled)
            VALUES (?, ?, TRUE) ON DUPLICATE KEY UPDATE enabled = TRUE`, pool, slot); err != nil {
			return fmt.Errorf("enable resource slot %s/%d: %w", pool, slot, err)
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE resource_slots
        SET enabled = FALSE
        WHERE pool = ? AND slot_number > ? AND job_id IS NULL`, pool, count); err != nil {
		return fmt.Errorf("disable excess resource slots for %s: %w", pool, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit resource pool update: %w", err)
	}
	return nil
}

func (r *Repository) Claim(ctx context.Context, workerID string, kinds []Kind, lease time.Duration) (*Claim, error) {
	if workerID == "" || len(kinds) == 0 || lease <= 0 {
		return nil, fmt.Errorf("invalid claim request")
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, fmt.Errorf("begin job claim: %w", err)
	}
	defer tx.Rollback()

	placeholders := make([]string, len(kinds))
	args := make([]any, len(kinds))
	for index, kind := range kinds {
		if _, ok := PoolForKind(kind); !ok {
			return nil, fmt.Errorf("unsupported job kind %q", kind)
		}
		placeholders[index] = "?"
		args[index] = string(kind)
	}
	query := `SELECT id, run_id, kind, fencing_token, attempt_count, max_attempts, created_at
        FROM jobs
        WHERE status = 'queued'
          AND available_at <= UTC_TIMESTAMP(6)
          AND attempt_count < max_attempts
          AND kind IN (` + strings.Join(placeholders, ",") + `)
        ORDER BY priority DESC, available_at, id
        LIMIT 1
        FOR UPDATE SKIP LOCKED`

	var claim Claim
	var kindValue string
	var oldFence uint64
	if err := tx.QueryRowContext(ctx, query, args...).Scan(
		&claim.ID, &claim.RunID, &kindValue, &oldFence, &claim.AttemptCount, &claim.MaxAttempts, &claim.CreatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("select claimable job: %w", err)
	}
	claim.Kind = Kind(kindValue)
	pool, ok := PoolForKind(claim.Kind)
	if !ok {
		return nil, fmt.Errorf("job %d has unsupported kind %q", claim.ID, claim.Kind)
	}
	claim.ResourcePool = pool
	claim.FencingToken = oldFence + 1

	var slotNumber uint32
	if err := tx.QueryRowContext(ctx, `SELECT slot_number
        FROM resource_slots
        WHERE pool = ? AND enabled = TRUE AND job_id IS NULL
        ORDER BY slot_number
        LIMIT 1
        FOR UPDATE SKIP LOCKED`, pool).Scan(&slotNumber); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("claim resource slot for %s: %w", pool, err)
	}

	leaseSeconds := int64(lease / time.Second)
	result, err := tx.ExecContext(ctx, `UPDATE jobs
        SET status = 'leased',
            claim_count = claim_count + 1,
            fencing_token = ?,
            lease_owner = ?,
            lease_until = DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? SECOND),
            heartbeat_at = UTC_TIMESTAMP(6)
        WHERE id = ? AND status = 'queued' AND fencing_token = ?`,
		claim.FencingToken, workerID, leaseSeconds, claim.ID, oldFence)
	if err != nil {
		return nil, fmt.Errorf("lease job %d: %w", claim.ID, err)
	}
	if err := requireOneRow(result); err != nil {
		return nil, ErrFenceLost
	}
	slotResult, err := tx.ExecContext(ctx, `UPDATE resource_slots
        SET job_id = ?, fencing_token = ?, lease_owner = ?, acquired_at = UTC_TIMESTAMP(6)
        WHERE pool = ? AND slot_number = ? AND job_id IS NULL`,
		claim.ID, claim.FencingToken, workerID, pool, slotNumber)
	if err != nil {
		return nil, fmt.Errorf("assign resource slot %s/%d: %w", pool, slotNumber, err)
	}
	if err := requireOneRow(slotResult); err != nil {
		return nil, ErrFenceLost
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit job claim: %w", err)
	}
	return &claim, nil
}

func (r *Repository) Start(ctx context.Context, workerID string, claim Claim) (uint32, error) {
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return 0, fmt.Errorf("begin job start: %w", err)
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx, `UPDATE jobs
        SET status = 'running', attempt_count = attempt_count + 1
        WHERE id = ? AND status = 'leased' AND lease_owner = ?
          AND fencing_token = ? AND lease_until > UTC_TIMESTAMP(6)`,
		claim.ID, workerID, claim.FencingToken)
	if err != nil {
		return 0, fmt.Errorf("start job %d: %w", claim.ID, err)
	}
	if err := requireOneRow(result); err != nil {
		return 0, ErrFenceLost
	}
	attemptNumber := claim.AttemptCount + 1
	if _, err := tx.ExecContext(ctx, `INSERT INTO job_attempts
        (job_id, attempt_number, worker_id, fencing_token, status)
        VALUES (?, ?, ?, ?, 'running')`,
		claim.ID, attemptNumber, workerID, claim.FencingToken); err != nil {
		return 0, fmt.Errorf("create attempt for job %d: %w", claim.ID, err)
	}
	runResult, err := tx.ExecContext(ctx, `UPDATE runs
        SET status = 'running', started_at = COALESCE(started_at, UTC_TIMESTAMP(6))
		WHERE id = ? AND status = 'queued'`, claim.RunID)
	if err != nil {
		return 0, fmt.Errorf("start run %s: %w", claim.RunID, err)
	}
	if err := requireOneRow(runResult); err != nil {
		return 0, ErrFenceLost
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit job start: %w", err)
	}
	return attemptNumber, nil
}

func (r *Repository) Heartbeat(ctx context.Context, workerID string, claim Claim, lease time.Duration) error {
	leaseSeconds := int64(lease / time.Second)
	result, err := r.db.ExecContext(ctx, `UPDATE jobs
        SET heartbeat_at = UTC_TIMESTAMP(6),
            lease_until = DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? SECOND)
        WHERE id = ? AND status IN ('leased', 'running')
          AND lease_owner = ? AND fencing_token = ? AND lease_until > UTC_TIMESTAMP(6)`,
		leaseSeconds, claim.ID, workerID, claim.FencingToken)
	if err != nil {
		return fmt.Errorf("heartbeat job %d: %w", claim.ID, err)
	}
	if err := requireOneRow(result); err != nil {
		return ErrFenceLost
	}
	return nil
}

func (r *Repository) Complete(ctx context.Context, workerID string, claim Claim, attempt uint32, completion Completion) error {
	if completion.RunStatus == "" || completion.JobStatus == "" || completion.AttemptStatus == "" {
		return fmt.Errorf("completion status is incomplete")
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("begin job completion: %w", err)
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx, `UPDATE jobs
        SET status = ?, lease_owner = NULL, lease_until = NULL, heartbeat_at = NULL
        WHERE id = ? AND status = 'running' AND lease_owner = ?
          AND fencing_token = ? AND lease_until > UTC_TIMESTAMP(6)`,
		completion.JobStatus, claim.ID, workerID, claim.FencingToken)
	if err != nil {
		return fmt.Errorf("complete job %d: %w", claim.ID, err)
	}
	if err := requireOneRow(result); err != nil {
		return ErrFenceLost
	}
	attemptResult, err := tx.ExecContext(ctx, `UPDATE job_attempts
        SET status = ?, error_code = NULLIF(?, ''), error_message = NULLIF(?, ''), completed_at = UTC_TIMESTAMP(6)
        WHERE job_id = ? AND attempt_number = ? AND fencing_token = ? AND status = 'running'`,
		completion.AttemptStatus, completion.ErrorCode, completion.ErrorMessage,
		claim.ID, attempt, claim.FencingToken)
	if err != nil {
		return fmt.Errorf("complete attempt for job %d: %w", claim.ID, err)
	}
	if err := requireOneRow(attemptResult); err != nil {
		return ErrFenceLost
	}
	runResult, err := tx.ExecContext(ctx, `UPDATE runs
        SET status = ?, error_code = NULLIF(?, ''), error_message = NULLIF(?, ''), completed_at = UTC_TIMESTAMP(6)
        WHERE id = ? AND status = 'running'`,
		completion.RunStatus, completion.ErrorCode, completion.ErrorMessage, claim.RunID)
	if err != nil {
		return fmt.Errorf("complete run %s: %w", claim.RunID, err)
	}
	if err := requireOneRow(runResult); err != nil {
		return ErrFenceLost
	}
	if err := updateTaskForCompletion(ctx, tx, claim, completion); err != nil {
		return err
	}
	slotResult, err := tx.ExecContext(ctx, `UPDATE resource_slots
        SET job_id = NULL, fencing_token = NULL, lease_owner = NULL, acquired_at = NULL
        WHERE job_id = ? AND fencing_token = ? AND lease_owner = ?`,
		claim.ID, claim.FencingToken, workerID)
	if err != nil {
		return fmt.Errorf("release resource slot for job %d: %w", claim.ID, err)
	}
	if err := requireOneRow(slotResult); err != nil {
		return ErrFenceLost
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit job completion: %w", err)
	}
	return nil
}

func (r *Repository) Retry(
	ctx context.Context,
	workerID string,
	claim Claim,
	attempt uint32,
	delay time.Duration,
	errorCode string,
	errorMessage string,
) error {
	if delay < time.Second {
		delay = time.Second
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("begin job retry: %w", err)
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx, `UPDATE jobs
        SET status = 'queued', available_at = DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? SECOND),
            lease_owner = NULL, lease_until = NULL, heartbeat_at = NULL
        WHERE id = ? AND status = 'running' AND lease_owner = ?
          AND fencing_token = ? AND lease_until > UTC_TIMESTAMP(6)`,
		int64(delay/time.Second), claim.ID, workerID, claim.FencingToken)
	if err != nil {
		return fmt.Errorf("requeue job %d: %w", claim.ID, err)
	}
	if err := requireOneRow(result); err != nil {
		return ErrFenceLost
	}
	attemptResult, err := tx.ExecContext(ctx, `UPDATE job_attempts
        SET status = 'failed', error_code = NULLIF(?, ''), error_message = NULLIF(?, ''),
            completed_at = UTC_TIMESTAMP(6)
        WHERE job_id = ? AND attempt_number = ? AND fencing_token = ? AND status = 'running'`,
		errorCode, errorMessage, claim.ID, attempt, claim.FencingToken)
	if err != nil {
		return fmt.Errorf("record retry for job %d: %w", claim.ID, err)
	}
	if err := requireOneRow(attemptResult); err != nil {
		return ErrFenceLost
	}
	runResult, err := tx.ExecContext(ctx, `UPDATE runs
        SET status = 'queued', error_code = NULL, error_message = NULL
		WHERE id = ? AND status = 'running'`, claim.RunID)
	if err != nil {
		return fmt.Errorf("requeue run %s: %w", claim.RunID, err)
	}
	if err := requireOneRow(runResult); err != nil {
		return ErrFenceLost
	}
	slotResult, err := tx.ExecContext(ctx, `UPDATE resource_slots
        SET job_id = NULL, fencing_token = NULL, lease_owner = NULL, acquired_at = NULL
        WHERE job_id = ? AND fencing_token = ? AND lease_owner = ?`,
		claim.ID, claim.FencingToken, workerID)
	if err != nil {
		return fmt.Errorf("release retry slot for job %d: %w", claim.ID, err)
	}
	if err := requireOneRow(slotResult); err != nil {
		return ErrFenceLost
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit retry for job %d: %w", claim.ID, err)
	}
	return nil
}

func (r *Repository) PublicationComplete(ctx context.Context, claim Claim) (bool, error) {
	var published bool
	if err := r.db.QueryRowContext(ctx, `SELECT published_at IS NOT NULL
        FROM runs WHERE id = ?`, claim.RunID).Scan(&published); err != nil {
		return false, fmt.Errorf("inspect publication state for run %s: %w", claim.RunID, err)
	}
	return published, nil
}

func (r *Repository) WithFence(ctx context.Context, claim Claim, apply func(*sql.Tx) error) error {
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("begin fenced publication: %w", err)
	}
	defer tx.Rollback()
	var valid int
	if err := tx.QueryRowContext(ctx, `SELECT 1 FROM jobs
        WHERE id = ? AND run_id = ? AND status = 'running' AND fencing_token = ?
          AND lease_until > UTC_TIMESTAMP(6) FOR UPDATE`, claim.ID, claim.RunID, claim.FencingToken).Scan(&valid); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrFenceLost
		}
		return fmt.Errorf("validate publication fence: %w", err)
	}
	if err := apply(tx); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE runs
        SET published_at = COALESCE(published_at, UTC_TIMESTAMP(6))
        WHERE id = ?`, claim.RunID); err != nil {
		return fmt.Errorf("mark run %s publication complete: %w", claim.RunID, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit fenced publication: %w", err)
	}
	return nil
}

func updateTaskForCompletion(ctx context.Context, tx *sql.Tx, claim Claim, completion Completion) error {
	var status string
	switch claim.Kind {
	case KindScan:
		if completion.JobStatus == "failed" {
			status = "failed"
		}
	case KindTrivyScan:
		if completion.JobStatus == "succeeded" {
			status = "ready"
		} else {
			status = "partial"
		}
	}
	if status == "" {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE tasks t JOIN runs r ON r.task_id = t.id
        SET t.status = ? WHERE r.id = ? AND t.deleted_at IS NULL`, status, claim.RunID); err != nil {
		return fmt.Errorf("update task after %s completion: %w", claim.Kind, err)
	}
	return nil
}

func (r *Repository) RequeueExpired(ctx context.Context, limit int) (int, error) {
	if limit <= 0 {
		limit = 20
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return 0, fmt.Errorf("begin expired lease recovery: %w", err)
	}
	defer tx.Rollback()

	rows, err := tx.QueryContext(ctx, `SELECT j.id, j.run_id, j.kind, j.status, j.attempt_count,
		j.max_attempts, j.fencing_token, r.published_at IS NOT NULL
		FROM jobs j JOIN runs r ON r.id = j.run_id
		WHERE j.status IN ('leased', 'running') AND j.lease_until <= UTC_TIMESTAMP(6)
		ORDER BY j.lease_until, j.id
		LIMIT ? FOR UPDATE SKIP LOCKED`, limit)
	if err != nil {
		return 0, fmt.Errorf("select expired jobs: %w", err)
	}
	type expiredJob struct {
		id          uint64
		runID       string
		kind        Kind
		status      string
		attempts    uint32
		maxAttempts uint32
		fence       uint64
		published   bool
	}
	var expired []expiredJob
	for rows.Next() {
		var item expiredJob
		if err := rows.Scan(&item.id, &item.runID, &item.kind, &item.status, &item.attempts,
			&item.maxAttempts, &item.fence, &item.published); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan expired job: %w", err)
		}
		expired = append(expired, item)
	}
	if err := rows.Close(); err != nil {
		return 0, fmt.Errorf("close expired jobs: %w", err)
	}

	for _, item := range expired {
		if item.published {
			if _, err := tx.ExecContext(ctx, `UPDATE job_attempts
				SET status = 'succeeded', error_code = NULL, error_message = NULL,
					completed_at = UTC_TIMESTAMP(6)
				WHERE job_id = ? AND fencing_token = ? AND status = 'running'`, item.id, item.fence); err != nil {
				return 0, fmt.Errorf("finalize published attempt for job %d: %w", item.id, err)
			}
			if _, err := tx.ExecContext(ctx, `UPDATE jobs
				SET status = 'succeeded', lease_owner = NULL, lease_until = NULL, heartbeat_at = NULL
				WHERE id = ? AND fencing_token = ?`, item.id, item.fence); err != nil {
				return 0, fmt.Errorf("finalize published job %d: %w", item.id, err)
			}
			if _, err := tx.ExecContext(ctx, `UPDATE runs
				SET status = 'complete', error_code = NULL, error_message = NULL,
					completed_at = COALESCE(completed_at, UTC_TIMESTAMP(6))
				WHERE id = ?`, item.runID); err != nil {
				return 0, fmt.Errorf("finalize published run %s: %w", item.runID, err)
			}
			claim := Claim{ID: item.id, RunID: item.runID, Kind: item.kind, FencingToken: item.fence}
			if err := updateTaskForCompletion(ctx, tx, claim, Completion{JobStatus: "succeeded"}); err != nil {
				return 0, err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE resource_slots
				SET job_id = NULL, fencing_token = NULL, lease_owner = NULL, acquired_at = NULL
				WHERE job_id = ? AND fencing_token = ?`, item.id, item.fence); err != nil {
				return 0, fmt.Errorf("release published job slot %d: %w", item.id, err)
			}
			continue
		}
		if item.status == "running" {
			if _, err := tx.ExecContext(ctx, `UPDATE job_attempts
                SET status = 'lease_lost', error_code = 'lease_expired', completed_at = UTC_TIMESTAMP(6)
                WHERE job_id = ? AND fencing_token = ? AND status = 'running'`, item.id, item.fence); err != nil {
				return 0, fmt.Errorf("expire attempt for job %d: %w", item.id, err)
			}
		}
		if item.attempts < item.maxAttempts {
			if _, err := tx.ExecContext(ctx, `UPDATE jobs
                SET status = 'queued', available_at = DATE_ADD(UTC_TIMESTAMP(6), INTERVAL 5 SECOND),
                    lease_owner = NULL, lease_until = NULL, heartbeat_at = NULL
                WHERE id = ? AND fencing_token = ?`, item.id, item.fence); err != nil {
				return 0, fmt.Errorf("requeue expired job %d: %w", item.id, err)
			}
			if _, err := tx.ExecContext(ctx, `UPDATE runs SET status = 'queued' WHERE id = ? AND status = 'running'`, item.runID); err != nil {
				return 0, fmt.Errorf("requeue run %s: %w", item.runID, err)
			}
		} else {
			if _, err := tx.ExecContext(ctx, `UPDATE jobs
                SET status = 'failed', lease_owner = NULL, lease_until = NULL, heartbeat_at = NULL
                WHERE id = ? AND fencing_token = ?`, item.id, item.fence); err != nil {
				return 0, fmt.Errorf("fail expired job %d: %w", item.id, err)
			}
			if _, err := tx.ExecContext(ctx, `UPDATE runs
                SET status = 'failed', error_code = 'attempts_exhausted', completed_at = UTC_TIMESTAMP(6)
                WHERE id = ?`, item.runID); err != nil {
				return 0, fmt.Errorf("fail run %s: %w", item.runID, err)
			}
			claim := Claim{ID: item.id, RunID: item.runID, Kind: item.kind, FencingToken: item.fence}
			if err := updateTaskForCompletion(ctx, tx, claim, Completion{JobStatus: "failed"}); err != nil {
				return 0, err
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE resource_slots
            SET job_id = NULL, fencing_token = NULL, lease_owner = NULL, acquired_at = NULL
            WHERE job_id = ? AND fencing_token = ?`, item.id, item.fence); err != nil {
			return 0, fmt.Errorf("release expired job slot %d: %w", item.id, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit expired lease recovery: %w", err)
	}
	return len(expired), nil
}

func requireOneRow(result sql.Result) error {
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrFenceLost
	}
	return nil
}
