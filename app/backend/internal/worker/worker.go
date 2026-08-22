package worker

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"binaryscan.local/backend/internal/config"
	"binaryscan.local/backend/internal/database"
	"binaryscan.local/backend/internal/job"
)

type Executor interface {
	Execute(context.Context, job.Claim) error
}

type Factory func(config.Config, *sql.DB, *job.Repository) (Executor, error)

const checkerRetryBudget = 12 * time.Hour

func Run(role string, kinds []job.Kind, factory Factory) error {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		cfg, err := config.Load(role)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		db, err := database.Open(ctx, cfg.Database)
		if err != nil {
			return err
		}
		return db.Close()
	}
	cfg, err := config.Load(role)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	db, err := openWithRetry(ctx, cfg.Database)
	if err != nil {
		return err
	}
	defer db.Close()
	repository := job.NewRepository(db)
	executor, err := factory(cfg, db, repository)
	if err != nil {
		return fmt.Errorf("initialize %s executor: %w", role, err)
	}
	for _, kind := range kinds {
		pool, ok := job.PoolForKind(kind)
		if !ok {
			return fmt.Errorf("role %s contains unsupported kind %q", role, kind)
		}
		if err := repository.EnsurePool(ctx, pool, cfg.Worker.SlotCounts[pool]); err != nil {
			return err
		}
	}

	hostname, _ := os.Hostname()
	workerID := role + ":" + hostname
	logger := slog.Default().With("role", role, "worker_id", workerID)
	logger.Info("worker started", "job_kinds", kinds)

	reaperTicker := time.NewTicker(15 * time.Second)
	defer reaperTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-reaperTicker.C:
			if count, err := repository.RequeueExpired(ctx, 20); err != nil {
				logger.Error("lease recovery failed", "error", err)
			} else if count > 0 {
				logger.Warn("recovered expired jobs", "count", count)
			}
		default:
		}

		claim, err := repository.Claim(ctx, workerID, kinds, cfg.Worker.Lease)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			logger.Error("claim failed", "error", err)
			sleepContext(ctx, cfg.Worker.Poll)
			continue
		}
		if claim == nil {
			sleepContext(ctx, cfg.Worker.Poll)
			continue
		}
		attempt, err := repository.Start(ctx, workerID, *claim)
		if err != nil {
			logger.Warn("job start rejected", "job_id", claim.ID, "error", err)
			continue
		}
		published, err := repository.PublicationComplete(ctx, *claim)
		if err != nil {
			err = job.Retryable(err, 5*time.Second)
		} else if published {
			logger.Info("skipping previously published job", "job_id", claim.ID, "run_id", claim.RunID)
		} else {
			executionCtx, executionCancel := executionContext(ctx, *claim)
			err = executeWithHeartbeat(executionCtx, repository, workerID, *claim, cfg.Worker.Lease, cfg.Worker.Heartbeat, executor)
			executionCancel()
			if err != nil {
				committed, inspectErr := repository.PublicationComplete(ctx, *claim)
				if inspectErr == nil && committed {
					logger.Warn("execution returned after publication; treating committed result as successful",
						"job_id", claim.ID, "run_id", claim.RunID, "error", err)
					err = nil
				}
			}
		}
		var retryable *job.RetryableError
		if errors.As(err, &retryable) && canRetry(*claim, retryable.Delay) {
			if retryErr := repository.Retry(ctx, workerID, *claim, attempt, retryable.Delay,
				"dependency_unavailable", truncate(retryable.Error(), 1024)); retryErr != nil {
				logger.Error("job retry rejected", "job_id", claim.ID, "error", retryErr)
			} else {
				logger.Warn("job deferred", "job_id", claim.ID, "kind", claim.Kind, "retry_after", retryable.Delay)
			}
			continue
		}
		completion := job.Completion{RunStatus: "complete", JobStatus: "succeeded", AttemptStatus: "succeeded"}
		if err != nil {
			completion = job.Completion{
				RunStatus:     "failed",
				JobStatus:     "failed",
				AttemptStatus: "failed",
				ErrorCode:     errorCode(err),
				ErrorMessage:  truncate(err.Error(), 1024),
			}
		}
		if completeErr := repository.Complete(ctx, workerID, *claim, attempt, completion); completeErr != nil {
			logger.Error("job completion rejected", "job_id", claim.ID, "error", completeErr)
			continue
		}
		logger.Info("job completed", "job_id", claim.ID, "kind", claim.Kind, "status", completion.JobStatus)
	}
}

func executionContext(parent context.Context, claim job.Claim) (context.Context, context.CancelFunc) {
	if isCheckerKind(claim.Kind) {
		return context.WithDeadline(parent, claim.CreatedAt.Add(checkerRetryBudget))
	}
	return context.WithCancel(parent)
}

func canRetry(claim job.Claim, delay time.Duration) bool {
	if claim.AttemptCount+1 >= claim.MaxAttempts {
		return false
	}
	if !isCheckerKind(claim.Kind) {
		return true
	}
	return time.Now().UTC().Add(delay).Before(claim.CreatedAt.Add(checkerRetryBudget))
}

func isCheckerKind(kind job.Kind) bool {
	return kind == job.KindCCheck || kind == job.KindJavaCheck || kind == job.KindPythonCheck
}

func executeWithHeartbeat(
	ctx context.Context,
	repository *job.Repository,
	workerID string,
	claim job.Claim,
	lease time.Duration,
	heartbeat time.Duration,
	executor Executor,
) error {
	executionCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- executor.Execute(executionCtx, claim) }()
	ticker := time.NewTicker(heartbeat)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			return err
		case <-ticker.C:
			if err := repository.Heartbeat(ctx, workerID, claim, lease); err != nil {
				cancel()
				return err
			}
		case <-ctx.Done():
			cancel()
			return ctx.Err()
		}
	}
}

func openWithRetry(ctx context.Context, cfg config.Database) (*sql.DB, error) {
	var lastErr error
	for ctx.Err() == nil {
		db, err := database.Open(ctx, cfg)
		if err == nil {
			return db, nil
		}
		lastErr = err
		sleepContext(ctx, 2*time.Second)
	}
	return nil, fmt.Errorf("database did not become available: %w", lastErr)
}

func sleepContext(ctx context.Context, delay time.Duration) {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

func errorCode(err error) string {
	if errors.Is(err, job.ErrFenceLost) {
		return "fence_lost"
	}
	return "execution_failed"
}

func truncate(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}
