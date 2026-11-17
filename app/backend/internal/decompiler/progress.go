package decompiler

import (
	"context"
	"strconv"
	"strings"

	"binaryscan.local/backend/internal/job"
)

const toolProgressPrefix = "BINARYSCAN_PROGRESS "

// toolProgressWriter accepts only the bounded counter protocol emitted by our
// tool adapters. It drains all other output and bounds incomplete log lines.
type toolProgressWriter struct {
	ctx      context.Context
	pending  []byte
	dropping bool
}

func (w *toolProgressWriter) Write(body []byte) (int, error) {
	for _, c := range body {
		if c == '\n' || c == '\r' {
			if !w.dropping {
				w.line(string(w.pending))
			}
			w.pending = w.pending[:0]
			w.dropping = false
		} else if !w.dropping {
			if len(w.pending) >= 1024 {
				w.pending = w.pending[:0]
				w.dropping = true
			} else {
				w.pending = append(w.pending, c)
			}
		}
	}
	return len(body), nil
}

func (w *toolProgressWriter) line(line string) {
	// Ghidra prefixes script println output with its logger name.
	start := strings.Index(line, toolProgressPrefix)
	if start < 0 {
		return
	}
	fields := strings.Fields(line[start+len(toolProgressPrefix):])
	if len(fields) < 4 || fields[0] != "decompiling" {
		return
	}
	current, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return
	}
	total, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil || total <= 0 || total > 1_000_000 {
		return
	}
	if fields[3] != "classes" && fields[3] != "functions" {
		return
	}
	job.ReportProgress(w.ctx, fields[0], current, total, fields[3])
}
