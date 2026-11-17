package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"binaryscan.local/backend/internal/job"
	"github.com/gin-gonic/gin"
)

func TestWorkerProgressSurvivesEventNormalization(t *testing.T) {
	kind, payload := normalizeTaskEvent("analysis.progress", `{"analyzer":"java-checker","phase":"analyzing","current":106,"total":532,"run_id":"run-1","heartbeat":true,"elapsed_seconds":45}`)
	if kind != "analysis.progress" || payload["current"] != float64(106) || payload["run_id"] != "run-1" || payload["heartbeat"] != true || eventStage(kind) != "SCANNING" {
		t.Fatalf("lost structured analysis progress: %s, %+v", kind, payload)
	}
	value, indeterminate := eventProgress(sql.NullInt64{Int64: 106, Valid: true}, sql.NullInt64{Int64: 532, Valid: true})
	if indeterminate || value.(float64) < 19 || value.(float64) > 20 {
		t.Fatalf("counter percentage: %v, %v", value, indeterminate)
	}
	if _, unknown := eventProgress(sql.NullInt64{}, sql.NullInt64{}); !unknown {
		t.Fatal("invented progress for unmeasurable phase")
	}
}

func TestInternalToolDiagnosticsAdvanceCursorWithoutStreaming(t *testing.T) {
	s := cleanupTestService(t)
	cleanupBlob(t, s, "blob")
	cleanupTask(t, s, "task", "blob", "", "binary")
	internal := strings.Repeat("private tool error ", 200)
	cleanupExec(t, s, `INSERT INTO task_events (task_id, event_type, message) VALUES ('task', 'decompile.diagnostics', ?)`, internal)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	last, err := s.writeTaskEvents(c, "task", 0)
	if err != nil || last == 0 || w.Body.Len() != 0 {
		t.Fatalf("internal log streamed or replay cursor stuck: cursor=%d body=%s err=%v", last, w.Body.String(), err)
	}
	var stored string
	if err := s.db.QueryRow(`SELECT message FROM task_events WHERE id = ?`, last).Scan(&stored); err != nil || stored != internal {
		t.Fatalf("extended diagnostic was not retained for export: %v", err)
	}
}

func TestProgressRejectsStaleFenceAndFailureTerminatesExactRun(t *testing.T) {
	s := cleanupTestService(t)
	cleanupBlob(t, s, "blob")
	cleanupTask(t, s, "task", "blob", "", "binary")
	cleanupExec(t, s, `INSERT INTO runs (id, kind, status, task_id, subject_type, subject_id, idempotency_key)
		VALUES ('run', 'java_check', 'running', 'task', 'source_project', 'project', 'run')`)
	cleanupExec(t, s, `INSERT INTO jobs (id, run_id, kind, status, fencing_token, lease_owner, lease_until)
		VALUES (99, 'run', 'java_check', 'running', 7, 'worker', DATE_ADD(UTC_TIMESTAMP(6), INTERVAL 60 SECOND))`)
	cleanupExec(t, s, `INSERT INTO job_attempts (job_id, attempt_number, worker_id, fencing_token, status)
		VALUES (99, 1, 'worker', 7, 'running')`)
	cleanupExec(t, s, `INSERT INTO resource_slots (pool, slot_number, job_id, fencing_token, lease_owner)
		VALUES ('java-check', 1, 99, 7, 'worker')`)
	repository := job.NewRepository(s.db)
	claim := job.Claim{ID: 99, RunID: "run", Kind: job.KindJavaCheck, FencingToken: 7}
	progressCtx, stop := repository.TrackProgress(context.Background(), claim)
	job.ReportProgress(progressCtx, "analyzing", 10, 100, "files")
	stop()
	fullFailure := strings.Repeat("source failure details ", 200)
	repository.RecordExecutionDiagnostic(context.Background(), claim, errors.New(fullFailure))
	var retained string
	if err := s.db.QueryRow(`SELECT JSON_UNQUOTE(JSON_EXTRACT(message, '$.error')) FROM task_events WHERE event_type = 'analysis.diagnostics'`).Scan(&retained); err != nil || retained != fullFailure {
		t.Fatalf("execution diagnostic lost content beyond public 1024-byte error limit: %v", err)
	}
	var before, after int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM task_events WHERE task_id = 'task'`).Scan(&before)
	stale := claim
	stale.FencingToken = 6
	_, stopStale := repository.TrackProgress(context.Background(), stale)
	stopStale()
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM task_events WHERE task_id = 'task'`).Scan(&after)
	if before != 3 || before != after {
		t.Fatalf("stale progress mutated task: before=%d after=%d", before, after)
	}
	if err := repository.Complete(context.Background(), "worker", claim, 1, job.Completion{RunStatus: "failed", JobStatus: "failed", AttemptStatus: "failed", ErrorCode: "execution_failed", ErrorMessage: "invalid source"}); err != nil {
		t.Fatal(err)
	}
	var eventType, message string
	var created time.Time
	if err := s.db.QueryRow(`SELECT event_type, message, created_at FROM task_events WHERE task_id = 'task' ORDER BY id DESC LIMIT 1`).Scan(&eventType, &message, &created); err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(message), &payload); err != nil {
		t.Fatal(err)
	}
	if eventType != "analysis.failed" || payload["run_id"] != "run" || payload["phase"] != "failed" {
		t.Fatalf("failure left run progress active: %s %+v", eventType, payload)
	}
}

func TestLongPublicationDoesNotLoseLeaseToHeartbeatOrProgress(t *testing.T) {
	s := cleanupTestService(t)
	cleanupBlob(t, s, "blob")
	cleanupTask(t, s, "task", "blob", "", "binary")
	cleanupExec(t, s, `INSERT INTO runs (id, kind, status, task_id, subject_type, subject_id, idempotency_key)
		VALUES ('run', 'jvm_decompile', 'running', 'task', 'file_node', 'file-task', 'run')`)
	cleanupExec(t, s, `INSERT INTO jobs (id, run_id, kind, status, fencing_token, lease_owner, heartbeat_at, lease_until)
		VALUES (99, 'run', 'jvm_decompile', 'running', 7, 'worker', UTC_TIMESTAMP(6), DATE_ADD(UTC_TIMESTAMP(6), INTERVAL 60 SECOND))`)
	cleanupExec(t, s, `INSERT INTO job_attempts (job_id, attempt_number, worker_id, fencing_token, status)
		VALUES (99, 1, 'worker', 7, 'running')`)
	cleanupExec(t, s, `INSERT INTO resource_slots (pool, slot_number, job_id, fencing_token, lease_owner)
		VALUES ('jvm', 1, 99, 7, 'worker')`)
	repository := job.NewRepository(s.db)
	claim := job.Claim{ID: 99, RunID: "run", Kind: job.KindJVMDecompile, FencingToken: 7}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	locked, release := make(chan struct{}), make(chan struct{})
	published := make(chan error, 1)
	cleanupExec(t, s, `UPDATE jobs SET heartbeat_at = UTC_TIMESTAMP(6), lease_until = DATE_ADD(UTC_TIMESTAMP(6), INTERVAL 2 SECOND) WHERE id = 99`)
	go func() {
		published <- repository.WithFence(ctx, claim, func(*sql.Tx) error {
			close(locked)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	select {
	case <-locked:
	case err := <-published:
		t.Fatalf("publication did not acquire fence: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	// A one-second MySQL lock_wait_timeout (set through the opt-in test DSN)
	// reproduces the production 50-second timeout without a long-running test.
	// Both operations must immediately skip the lock held by publication.
	if err := repository.Heartbeat(ctx, "worker", claim, 2*time.Second); err != nil {
		t.Fatalf("heartbeat cancelled publication while its fence was locked: %v", err)
	}
	if err := repository.RecordObservation(ctx, claim, "decompile.progress", `{"phase":"publishing"}`, 0, 1, true); err != nil {
		t.Fatalf("progress waited on publication: %v", err)
	}
	stale := claim
	stale.FencingToken--
	if err := repository.Heartbeat(ctx, "worker", stale, 2*time.Second); !errors.Is(err, job.ErrFenceLost) {
		t.Fatalf("busy publication masked a stale fence: %v", err)
	}
	timer := time.NewTimer(2200 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := repository.Heartbeat(ctx, "worker", claim, 2*time.Second); err != nil {
		t.Fatalf("publication outlasting its lease was cancelled: %v", err)
	}
	if count, err := repository.RequeueExpired(ctx, 10); err != nil || count != 0 {
		t.Fatalf("reaper stole locked publication: count=%d err=%v", count, err)
	}
	close(release)
	if err := <-published; err != nil {
		t.Fatalf("publication rolled back: %v", err)
	}
	var live bool
	if err := s.db.QueryRow(`SELECT lease_until > UTC_TIMESTAMP(6) FROM jobs WHERE id = 99`).Scan(&live); err != nil || !live {
		t.Fatalf("publication released an expired lease: live=%v err=%v", live, err)
	}
	if err := repository.Heartbeat(ctx, "worker", claim, 30*time.Second); err != nil {
		t.Fatalf("heartbeat rejected just-published result: %v", err)
	}
	if err := repository.Complete(ctx, "worker", claim, 1, job.Completion{RunStatus: "complete", JobStatus: "succeeded", AttemptStatus: "succeeded"}); err != nil {
		t.Fatalf("could not complete published result: %v", err)
	}
	complete, err := repository.PublicationComplete(ctx, claim)
	if err != nil || !complete {
		t.Fatalf("published result was lost: %v, %v", complete, err)
	}
	cleanupCount(t, s, `SELECT COUNT(*) FROM task_events WHERE event_type = 'decompile.progress'`, 0)
}

func TestSourceCompletionKeepsAnalyzerWorkflow(t *testing.T) {
	for _, language := range []string{"JAVA", "C", "PYTHON"} {
		kind, payload := normalizeTaskEvent("check.complete", language+" 源码检查完成，发现 3 条问题")
		if kind != "analysis.completed" || payload["phase"] != "completed" || payload["finding_count"] != int64(3) {
			t.Fatalf("lost source workflow: %s %+v", kind, payload)
		}
	}
}
