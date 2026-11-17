package decompiler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"binaryscan.local/backend/internal/job"
)

type transcriptContextKey struct{}

type commandTranscript struct {
	Tool      string   `json:"tool"`
	Arguments []string `json:"arguments"`
	Stdout    string   `json:"stdout"`
	Stderr    string   `json:"stderr"`
	Error     string   `json:"error,omitempty"`
	Truncated bool     `json:"truncated"`
	stdout    bytes.Buffer
	stderr    bytes.Buffer
}

// The budget applies to the entire run, including all nested application jars
// and fallback attempts. Truncation never prevents later errors being recorded.
type toolTranscript struct {
	mu          sync.Mutex
	commands    []*commandTranscript
	diagnostics []string
	bytes       int
	truncated   bool
}

type transcriptWriter struct {
	transcript *toolTranscript
	command    *commandTranscript
	stderr     bool
}

func (w transcriptWriter) Write(body []byte) (int, error) {
	w.transcript.mu.Lock()
	defer w.transcript.mu.Unlock()
	original := len(body)
	remaining := maxToolLogBytes - w.transcript.bytes
	if len(body) > remaining {
		body = body[:remaining]
		w.command.Truncated, w.transcript.truncated = true, true
	}
	if w.stderr {
		_, _ = w.command.stderr.Write(body)
	} else {
		_, _ = w.command.stdout.Write(body)
	}
	w.transcript.bytes += len(body)
	return original, nil
}

func toolLog(ctx context.Context, executable string, args []string) (io.Writer, io.Writer, func(error)) {
	transcript, ok := ctx.Value(transcriptContextKey{}).(*toolTranscript)
	if !ok {
		return io.Discard, io.Discard, func(error) {}
	}
	transcript.mu.Lock()
	if len(transcript.commands) >= 256 {
		transcript.truncated = true
		transcript.mu.Unlock()
		return io.Discard, io.Discard, func(error) {}
	}
	command := &commandTranscript{Tool: filepath.Base(executable), Arguments: append([]string(nil), args...)}
	transcript.commands = append(transcript.commands, command)
	transcript.mu.Unlock()
	return transcriptWriter{transcript: transcript, command: command}, transcriptWriter{transcript: transcript, command: command, stderr: true}, func(err error) {
		transcript.mu.Lock()
		defer transcript.mu.Unlock()
		command.Stdout, command.Stderr = command.stdout.String(), command.stderr.String()
		if err != nil {
			command.Error = boundedDiagnostic(err.Error())
		}
	}
}

func noteToolDiagnostic(ctx context.Context, message string) {
	if transcript, ok := ctx.Value(transcriptContextKey{}).(*toolTranscript); ok {
		transcript.mu.Lock()
		defer transcript.mu.Unlock()
		if len(transcript.diagnostics) < 256 {
			transcript.diagnostics = append(transcript.diagnostics, boundedDiagnostic(message))
		} else {
			transcript.truncated = true
		}
	}
}

func boundedDiagnostic(value string) string {
	if len(value) > 4096 {
		return strings.ToValidUTF8(value[:4096], "") + " [diagnostic truncated]"
	}
	return value
}

func (e *Executor) persistToolDiagnostics(ctx context.Context, claim job.Claim, transcript *toolTranscript) {
	transcript.mu.Lock()
	payload := struct {
		Version        string               `json:"version"`
		RunID          string               `json:"run_id"`
		Mode           Mode                 `json:"mode"`
		Commands       []*commandTranscript `json:"commands"`
		Diagnostics    []string             `json:"diagnostics"`
		Truncated      bool                 `json:"truncated"`
		LimitBytes     int                  `json:"log_limit_bytes"`
		TruncationNote string               `json:"truncation_note,omitempty"`
	}{Version: "decompile-diagnostics-v1", RunID: claim.RunID, Mode: e.mode, Commands: transcript.commands,
		Diagnostics: transcript.diagnostics, Truncated: transcript.truncated, LimitBytes: maxToolLogBytes}
	if transcript.truncated {
		payload.TruncationNote = fmt.Sprintf("Tool output was truncated at the per-run %d-byte limit; command errors and fallback diagnostics are retained separately.", maxToolLogBytes)
	}
	body, err := json.Marshal(payload)
	transcript.mu.Unlock()
	if err != nil {
		return
	}
	// Cancellation may terminate the tool; retain its failure transcript while
	// the worker still owns the lease. Deleted tasks and stale fences cannot write.
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	err = e.jobs.RecordObservation(writeCtx, claim, "decompile.diagnostics", string(body), nil, nil, false)
	if err != nil {
		slog.Warn("could not retain decompiler diagnostics", "run_id", claim.RunID, "error", err)
	}
}
