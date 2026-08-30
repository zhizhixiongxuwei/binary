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

// Executor 把通用的租约状态机与具体扫描、反编译或检测实现解耦。
type Executor interface {
	Execute(context.Context, job.Claim) error
}

// Factory 在 worker 完成数据库连接后构造对应角色的执行器。
type Factory func(config.Config, *sql.DB, *job.Repository) (Executor, error)

const checkerRetryBudget = 12 * time.Hour

// Run 驱动所有后台角色共享的任务状态机：领取租约、登记尝试、执行并续租，最后重试或完成。
// 执行本身允许因进程崩溃而至少一次发生；真正对外可见的结果由 Repository 的 fencing token
// 和 published_at 提交点保护，从而避免旧 worker 在租约转移后覆盖新结果。
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
		// 上一次执行可能已经提交业务结果、却在写回任务完成状态前崩溃；此时跳过重复副作用。
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
				// 执行器可能在事务提交后才因网络或上下文取消返回错误，以提交标记作为最终事实来源。
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

// executionContext 以任务创建时间而非单次尝试时间计算 checker 截止点，防止依赖长期不可用时
// 通过反复重试无限延长任务寿命。
func executionContext(parent context.Context, claim job.Claim) (context.Context, context.CancelFunc) {
	if isCheckerKind(claim.Kind) {
		return context.WithDeadline(parent, claim.CreatedAt.Add(checkerRetryBudget))
	}
	return context.WithCancel(parent)
}

// canRetry 同时受最大尝试次数和 checker 总重试预算约束。
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

// executeWithHeartbeat 在业务执行期间续租；一旦续租失败便取消执行上下文，促使已失去 fence 的
// worker 尽快停止。最终的持久化仍必须在 Repository.WithFence 内再次校验租约。
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

// openWithRetry 允许 worker 随依赖一起启动，并在数据库尚未就绪时等待到进程上下文取消。
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
