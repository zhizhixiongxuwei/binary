package decompiler

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestToolTranscriptRetainsSuccessfulAndFailedFallbackAttempts(t *testing.T) {
	transcript := &toolTranscript{}
	ctx := context.WithValue(context.Background(), transcriptContextKey{}, transcript)
	stdout, stderr, finish := toolLog(ctx, "/tools/vineflower", []string{"input.jar"})
	_, _ = stdout.Write([]byte("read class Example"))
	_, _ = stderr.Write([]byte("missing dependency"))
	finish(errors.New("exit status 1"))
	noteToolDiagnostic(ctx, "Vineflower failed; falling back to CFR")
	stdout, _, finish = toolLog(ctx, "/tools/cfr", nil)
	_, _ = stdout.Write([]byte("decompiled Example"))
	finish(nil)
	if len(transcript.commands) != 2 || transcript.commands[0].Stdout != "read class Example" || transcript.commands[0].Stderr != "missing dependency" || transcript.commands[0].Error == "" || transcript.commands[1].Stdout != "decompiled Example" || len(transcript.diagnostics) != 1 {
		t.Fatalf("fallback transcript incomplete: %+v", transcript)
	}
}

func TestToolTranscriptBoundsWholeRunButRetainsFailureAfterTruncation(t *testing.T) {
	transcript := &toolTranscript{}
	ctx := context.WithValue(context.Background(), transcriptContextKey{}, transcript)
	stdout, _, finish := toolLog(ctx, "vineflower", nil)
	log := []byte(strings.Repeat("x", maxToolLogBytes+100))
	if n, err := stdout.Write(log); n != len(log) || err != nil {
		t.Fatalf("failed to drain verbose tool: %d %v", n, err)
	}
	finish(nil)
	_, stderr, finish := toolLog(ctx, "cfr", nil)
	_, _ = stderr.Write([]byte("another log"))
	finish(errors.New("fallback failed"))
	noteToolDiagnostic(ctx, "fallback failure retained")
	if transcript.bytes != maxToolLogBytes || !transcript.truncated || !transcript.commands[0].Truncated || transcript.commands[1].Error != "fallback failed" || len(transcript.diagnostics) != 1 {
		t.Fatalf("unbounded log or lost post-truncation failure: %+v", transcript)
	}
}
