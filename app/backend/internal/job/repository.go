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
	query := `SELECT id, run_id, kind, fencing_token, attempt_count, max_attempts
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
		&claim.ID, &claim.RunID, &kindValue, &oldFence, &claim.AttemptCount, &claim.MaxAttempts,
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
	if _, err := tx.ExecContext(ctx, `UPDATE resource_slots
        SET job_id = ?, fencing_token = ?, lease_owner = ?, acquired_at = UTC_TIMESTAMP(6)
        WHERE pool = ? AND slot_number = ? AND job_id IS NULL`,
		claim.ID, claim.FencingToken, workerID, pool, slotNumber); err != nil {
		return nil, fmt.Errorf("assign resource slot %s/%d: %w", pool, slotNumber, err)
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
	if _, err := tx.ExecContext(ctx, `UPDATE runs
        SET status = 'running', started_at = COALESCE(started_at, UTC_TIMESTAMP(6))
        WHERE id = ? AND status = 'queued'`, claim.RunID); err != nil {
		return 0, fmt.Errorf("start run %s: %w", claim.RunID, err)
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
	if _, err := tx.ExecContext(ctx, `UPDATE job_attempts
        SET status = ?, error_code = NULLIF(?, ''), error_message = NULLIF(?, ''), completed_at = UTC_TIMESTAMP(6)
        WHERE job_id = ? AND attempt_number = ? AND fencing_token = ? AND status = 'running'`,
		completion.AttemptStatus, completion.ErrorCode, completion.ErrorMessage,
		claim.ID, attempt, claim.FencingToken); err != nil {
		return fmt.Errorf("complete attempt for job %d: %w", claim.ID, err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE runs
        SET status = ?, error_code = NULLIF(?, ''), error_message = NULLIF(?, ''), completed_at = UTC_TIMESTAMP(6)
        WHERE id = ? AND status = 'running'`,
		completion.RunStatus, completion.ErrorCode, completion.ErrorMessage, claim.RunID); err != nil {
		return fmt.Errorf("complete run %s: %w", claim.RunID, err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE resource_slots
        SET job_id = NULL, fencing_token = NULL, lease_owner = NULL, acquired_at = NULL
        WHERE job_id = ? AND fencing_token = ? AND lease_owner = ?`,
		claim.ID, claim.FencingToken, workerID); err != nil {
		return fmt.Errorf("release resource slot for job %d: %w", claim.ID, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit job completion: %w", err)
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

	rows, err := tx.QueryContext(ctx, `SELECT id, run_id, status, attempt_count, max_attempts, fencing_token
        FROM jobs
        WHERE status IN ('leased', 'running') AND lease_until <= UTC_TIMESTAMP(6)
        ORDER BY lease_until, id
        LIMIT ? FOR UPDATE SKIP LOCKED`, limit)
	if err != nil {
		return 0, fmt.Errorf("select expired jobs: %w", err)
	}
	type expiredJob struct {
		id          uint64
		runID       string
		status      string
		attempts    uint32
		maxAttempts uint32
		fence       uint64
	}
	var expired []expiredJob
	for rows.Next() {
		var item expiredJob
		if err := rows.Scan(&item.id, &item.runID, &item.status, &item.attempts, &item.maxAttempts, &item.fence); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan expired job: %w", err)
		}
		expired = append(expired, item)
	}
	if err := rows.Close(); err != nil {
		return 0, fmt.Errorf("close expired jobs: %w", err)
	}

	for _, item := range expired {
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
