package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"binaryscan.local/backend/internal/job"
)

// javaProjectAnalyzeCall keeps the project-wide call graph intact while polling
// its nonblocking progress endpoint. A legacy checker without /progress still
// works and receives the worker's activity heartbeat, without invented counters.
func javaProjectAnalyzeCall(ctx context.Context, session *javaProjectSession) ([]byte, error) {
	job.ReportProgress(ctx, "indexing", 0, 0, "files")
	pollCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-pollCtx.Done():
				return
			case <-ticker.C:
				requestCtx, requestCancel := context.WithTimeout(pollCtx, 3*time.Second)
				body, err := javaProjectCall(requestCtx, session.client, http.MethodGet, session.endpoint+"/progress", nil)
				requestCancel()
				if err == nil && pollCtx.Err() == nil {
					reportJavaProgress(ctx, body)
				}
			}
		}
	}()
	body, err := javaProjectCall(ctx, session.client, http.MethodPost, session.endpoint+"/analyze", nil)
	cancel()
	<-done
	return body, err
}

func reportJavaProgress(ctx context.Context, body []byte) {
	var value struct {
		Version string `json:"version"`
		Phase   string `json:"phase"`
		Current int64  `json:"current"`
		Total   int64  `json:"total"`
		Unit    string `json:"unit"`
	}
	if json.Unmarshal(body, &value) != nil || value.Version != javaProjectProtocol || value.Current < 0 || value.Total <= 0 || value.Total > 1_000_000 || value.Current > value.Total {
		return
	}
	switch value.Phase {
	case "parsing", "indexing", "analyzing":
	case "completed":
		// Final evidence still needs location validation and publication in Go.
		value.Phase = "analyzing"
	default:
		return
	}
	if value.Unit != "methods" && value.Unit != "steps" {
		value.Unit = "files"
	}
	job.ReportProgress(ctx, value.Phase, value.Current, value.Total, value.Unit)
}
