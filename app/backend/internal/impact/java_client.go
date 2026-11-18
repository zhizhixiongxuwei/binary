package impact

import (
	"binaryscan.local/backend/internal/checkrules"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type Input struct {
	SHA256      string `json:"sha256"`
	LogicalPath string `json:"logicalPath"`
	Size        int64  `json:"size"`
	Filename    string `json:"-"`
}
type Target struct {
	OccurrenceID  string   `json:"occurrenceId"`
	ComponentPath string   `json:"componentPath"`
	RuleID        string   `json:"ruleId"`
	Prefixes      []string `json:"prefixes"`
}
type JavaRequest struct {
	Schema          string   `json:"schemaVersion"`
	InputSHA256     string   `json:"inputSha256"`
	JavaRelease     int      `json:"javaRelease"`
	ApplicationType string   `json:"applicationType"`
	EntryPoints     []string `json:"entryPoints"`
	Inputs          []Input  `json:"inputs"`
	Targets         []Target `json:"targets"`
}
type JavaResponse struct {
	Schema      string                `json:"schemaVersion"`
	InputSHA256 string                `json:"inputSha256"`
	JavaRelease int                   `json:"javaRelease"`
	ViewDigest  string                `json:"viewDigest"`
	Results     map[string]CodeResult `json:"results"`
	Classes     int                   `json:"classes"`
	Methods     int                   `json:"methods"`
	Edges       int                   `json:"edges"`
	Diagnostics []string              `json:"diagnostics"`
}

func CallJava(ctx context.Context, base string, request JavaRequest) (JavaResponse, error) {
	var result JavaResponse
	client := &http.Client{Timeout: 200 * time.Second}
	base = checkrules.BaseURL(base) + "/v1/java-impact/sessions"
	send := func(ctx context.Context, method, url, contentType string, body io.Reader, size int64, value any) error {
		r, e := http.NewRequestWithContext(ctx, method, url, body)
		if e != nil {
			return e
		}
		r.Header.Set("Content-Type", contentType)
		if size >= 0 {
			r.ContentLength = size
		}
		response, e := client.Do(r)
		if e != nil {
			return e
		}
		defer response.Body.Close()
		b, e := io.ReadAll(io.LimitReader(response.Body, (16<<20)+1))
		if e != nil {
			return e
		}
		if len(b) > 16<<20 {
			return fmt.Errorf("JAVA_IMPACT_RESPONSE_LIMIT")
		}
		if response.StatusCode == 429 || response.StatusCode >= 500 {
			return fmt.Errorf("JAVA_IMPACT_UNAVAILABLE: %d", response.StatusCode)
		}
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			return fmt.Errorf("JAVA_IMPACT_PROTOCOL_ERROR: %d", response.StatusCode)
		}
		if value != nil {
			return json.Unmarshal(b, value)
		}
		return nil
	}
	body, e := json.Marshal(request)
	if e != nil {
		return result, e
	}
	var session struct {
		ID string `json:"sessionId"`
	}
	if e = send(ctx, http.MethodPost, base, "application/json", bytes.NewReader(body), int64(len(body)), &session); e != nil {
		return result, e
	}
	if len(session.ID) != 36 || strings.ContainsAny(session.ID, "/\\") {
		return result, fmt.Errorf("invalid impact session")
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = send(cleanup, http.MethodDelete, base+"/"+session.ID, "application/json", nil, 0, nil)
	}()
	for i, input := range request.Inputs {
		file, e := os.Open(input.Filename)
		if e != nil {
			return result, e
		}
		e = send(ctx, http.MethodPut, base+"/"+session.ID+"/inputs/"+strconv.Itoa(i), "application/octet-stream", file, input.Size, nil)
		file.Close()
		if e != nil {
			return result, e
		}
	}
	if e = send(ctx, http.MethodPost, base+"/"+session.ID+"/analyze", "application/json", nil, 0, &result); e != nil {
		return result, e
	}
	if result.Schema != "java-impact-v1" || result.InputSHA256 != request.InputSHA256 || result.JavaRelease != request.JavaRelease {
		return result, fmt.Errorf("JAVA_IMPACT_RESULT_IDENTITY_MISMATCH")
	}
	for _, target := range request.Targets {
		r, ok := result.Results[target.OccurrenceID]
		if !ok || r.InputSHA256 != request.InputSHA256 || r.RuleID != target.RuleID || r.State != "reachable" && r.State != "not_reachable" && r.State != "unknown" {
			return result, fmt.Errorf("JAVA_IMPACT_TARGET_IDENTITY_MISMATCH")
		}
	}
	return result, nil
}
