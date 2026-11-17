package job

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// Progress counts completed work in the current phase. A zero total means that
// the tool cannot yet measure that phase; elapsed time never invents progress.
type Progress struct {
	Phase         string `json:"phase"`
	Current       int64  `json:"current"`
	Total         int64  `json:"total"`
	Unit          string `json:"unit,omitempty"`
	ModuleCurrent int64  `json:"module_current"`
	ModuleTotal   int64  `json:"module_total,omitempty"`
	ModulePath    string `json:"module_path,omitempty"`
}

type progressContextKey struct{}
type progressSink func(Progress)

// ReportProgress is safe from concurrent tool callbacks and is a no-op outside
// a worker execution. Callers report actual counters, never a timer estimate.
func ReportProgress(ctx context.Context, phase string, current, total int64, unit string) {
	if sink, ok := ctx.Value(progressContextKey{}).(progressSink); ok {
		if current < 0 || total < 0 || total > 0 && current > total || phase == "" {
			return
		}
		sink(Progress{Phase: phase, Current: current, Total: total, Unit: unit})
	}
}

// WithProgressSink permits tool adapters and protocol clients to be tested
// without a database. It also carries the reporter through HTTP/tool contexts.
func WithProgressSink(ctx context.Context, sink func(Progress)) context.Context {
	return context.WithValue(ctx, progressContextKey{}, progressSink(sink))
}

// WithModuleProgress preserves an archive's completed-module count while a
// nested decompiler reports its own class counters. Consumers can combine the
// two ratios without resetting a large multi-module archive back to zero.
func WithModuleProgress(ctx context.Context, completed, total int64, path string) context.Context {
	parent, ok := ctx.Value(progressContextKey{}).(progressSink)
	if !ok {
		return ctx
	}
	return WithProgressSink(ctx, func(value Progress) {
		value.ModuleCurrent, value.ModuleTotal, value.ModulePath = completed, total, path
		parent(value)
	})
}

// TrackProgress publishes bounded updates and a 15-second activity heartbeat.
// Writes use the live job fence and do not set runs.published_at: progress is
// observable activity, not publication of the final result.
func (r *Repository) TrackProgress(ctx context.Context, claim Claim) (context.Context, func()) {
	eventType, analyzer := progressIdentity(claim.Kind)
	if eventType == "" {
		return ctx, func() {}
	}
	started := time.Now()
	var mu sync.Mutex
	latest := Progress{Phase: "preparing"}
	lastSent := Progress{}
	var lastWrite time.Time
	write := func(heartbeat bool) {
		payload := struct {
			Progress
			Analyzer       string `json:"analyzer"`
			RunID          string `json:"run_id"`
			Heartbeat      bool   `json:"heartbeat"`
			ElapsedSeconds int64  `json:"elapsed_seconds"`
		}{latest, analyzer, claim.RunID, heartbeat, int64(time.Since(started).Seconds())}
		body, _ := json.Marshal(payload)
		writeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		var current, total any
		if latest.Total > 0 {
			current, total = latest.Current, latest.Total
		}
		err := r.RecordObservation(writeCtx, claim, eventType, string(body), current, total, true)
		if err != nil && ctx.Err() == nil {
			slog.Warn("could not record worker progress", "run_id", claim.RunID, "error", err)
		}
		lastWrite, lastSent = time.Now(), latest
	}
	mu.Lock()
	write(false)
	mu.Unlock()
	progressCtx := WithProgressSink(ctx, func(value Progress) {
		mu.Lock()
		defer mu.Unlock()
		latest = value
		// Always send phase boundaries and completions; otherwise coalesce
		// rapid callbacks. The ticker flushes a final coalesced counter.
		if value.Phase != lastSent.Phase || value.Total > 0 && value.Current == value.Total || time.Since(lastWrite) >= time.Second {
			write(false)
		}
	})
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-stop:
				return
			case <-ticker.C:
				mu.Lock()
				if latest != lastSent || time.Since(lastWrite) >= 15*time.Second {
					write(latest == lastSent)
				}
				mu.Unlock()
			}
		}
	}()
	return progressCtx, func() { close(stop); <-done }
}

func progressIdentity(kind Kind) (string, string) {
	switch kind {
	case KindNativeDecompile:
		return "decompile.progress", "ghidra"
	case KindJVMDecompile:
		return "decompile.progress", "vineflower"
	case KindPYCDecompile:
		return "decompile.progress", "python-bytecode"
	case KindCCheck:
		return "analysis.progress", "c-checker"
	case KindJavaCheck:
		return "analysis.progress", "java-checker"
	case KindPythonCheck:
		return "analysis.progress", "python-checker"
	default:
		return "", ""
	}
}

// recordCompletionProgress runs inside Complete's fenced transaction, so even
// an executor failure has a terminal event with the exact run identity. It also
// closes the live progress bar when an older executor emits only a text event.
func recordCompletionProgress(ctx context.Context, tx *sql.Tx, claim Claim, completion Completion) error {
	eventType, analyzer := progressIdentity(claim.Kind)
	if eventType == "" {
		return nil
	}
	phase := "completed"
	if completion.RunStatus == "failed" {
		phase = "failed"
	} else if completion.RunStatus == "cancelled" {
		phase = "cancelled"
	}
	payload := map[string]any{"analyzer": analyzer, "run_id": claim.RunID, "phase": phase}
	var current, total any
	if phase == "completed" {
		current, total = 1, 1
		payload["current"], payload["total"] = 1, 1
	}
	if completion.ErrorCode != "" {
		payload["error_code"] = completion.ErrorCode
	}
	body, _ := json.Marshal(payload)
	eventType = strings.TrimSuffix(eventType, "progress") + phase
	_, err := tx.ExecContext(ctx, `INSERT INTO task_events
		(task_id, event_type, message, progress_current, progress_total)
		SELECT task_id, ?, ?, ?, ? FROM runs WHERE id = ?`, eventType, string(body), current, total, claim.RunID)
	return err
}

// RecordExecutionDiagnostic retains the executor's full failure before the
// worker reduces the public run/attempt error fields to their 1024-byte limit.
func (r *Repository) RecordExecutionDiagnostic(ctx context.Context, claim Claim, executionErr error) {
	eventType, analyzer := progressIdentity(claim.Kind)
	if eventType == "" || executionErr == nil {
		return
	}
	message := executionErr.Error()
	originalBytes := len(message)
	const diagnosticLimit = 1 << 20
	if len(message) > diagnosticLimit {
		message = strings.ToValidUTF8(message[:diagnosticLimit], "")
	}
	body, _ := json.Marshal(map[string]any{"version": "execution-diagnostics-v1", "run_id": claim.RunID,
		"analyzer": analyzer, "error": message, "truncated": originalBytes > diagnosticLimit, "original_bytes": originalBytes})
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	eventType = strings.TrimSuffix(eventType, "progress") + "diagnostics"
	err := r.RecordObservation(writeCtx, claim, eventType, string(body), nil, nil, false)
	if err != nil {
		slog.Warn("could not retain execution diagnostic", "run_id", claim.RunID, "error", err)
	}
}
