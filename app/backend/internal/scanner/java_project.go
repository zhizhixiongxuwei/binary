package scanner

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"binaryscan.local/backend/internal/checkrules"
	"binaryscan.local/backend/internal/job"
	"binaryscan.local/backend/internal/storage"
)

const javaProjectProtocol = "java-project-v1"

var errJavaProjectLimit = errors.New("Java project exceeds the project analysis input limit")
var errJavaRequestLimit = errors.New("Java project request exceeds the 64 MiB transport limit")

type checkerCoverage struct {
	TotalFiles      int `json:"totalFiles"`
	ParsedFiles     int `json:"parsedFiles"`
	FailedFiles     int `json:"failedFiles"`
	AnalyzedFiles   int `json:"analyzedFiles"`
	TotalMethods    int `json:"totalMethods"`
	AnalyzedMethods int `json:"analyzedMethods"`
	UnresolvedCalls int `json:"unresolvedCalls"`
}

type checkerDiagnostic struct {
	Code    string `json:"code"`
	Path    string `json:"path,omitempty"`
	Line    int    `json:"line,omitempty"`
	Column  int    `json:"column,omitempty"`
	Message string `json:"message"`
}

type javaProjectFile struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"sizeBytes"`
}

type javaProjectSession struct {
	client        *http.Client
	endpoint      string
	request       checkerRequest
	expectedFiles int
}

// A project session is bound to a frozen manifest and rule selection. Batches
// only transport files; they never divide the Java call graph into subprojects.
func createJavaProject(ctx context.Context, client *http.Client, checkerURL string, project checkerProject, manifest storage.Manifest, runID string) (*javaProjectSession, error) {
	files := make([]javaProjectFile, 0, len(manifest.Files))
	for _, file := range manifest.Files {
		if file.Language == "java" && file.SizeBytes <= 4<<20 {
			files = append(files, javaProjectFile{file.Path, strings.ToLower(file.SHA256), file.SizeBytes})
		}
	}
	request := checkerRequest{Version: "checker-v1", ProjectID: project.id, Language: "java"}
	if project.selection != nil {
		request.CatalogVersion = project.selection.CatalogVersion
		request.RuleIDs = project.selection.EnabledRuleIDs
	} else {
		// Legacy runs omitted a selection. Resolve and pin the current full
		// registry before the first source byte crosses the checker boundary.
		catalog, err := checkrules.Fetch(ctx, checkerURL, "java")
		if err != nil {
			return nil, err
		}
		selection, err := checkrules.Select(catalog, nil, catalog.CatalogVersion, true)
		if err != nil {
			return nil, err
		}
		request.CatalogVersion = selection.CatalogVersion
		request.RuleIDs = selection.EnabledRuleIDs
	}
	payload := struct {
		Version        string            `json:"version"`
		ProjectID      string            `json:"projectId"`
		RunID          string            `json:"runId"`
		ManifestSHA256 string            `json:"manifestSha256"`
		CatalogVersion string            `json:"catalogVersion,omitempty"`
		RuleIDs        []string          `json:"ruleIds,omitempty"`
		Files          []javaProjectFile `json:"files"`
	}{javaProjectProtocol, project.id, runID, hex.EncodeToString(project.manifestSHA256), request.CatalogVersion, request.RuleIDs, files}
	endpoint := checkrules.BaseURL(checkerURL) + "/v2/java/projects"
	body, err := javaProjectCall(ctx, client, http.MethodPost, endpoint, payload)
	if err != nil {
		return nil, err
	}
	var response struct {
		Version   string `json:"version"`
		SessionID string `json:"sessionId"`
	}
	if err := json.Unmarshal(body, &response); err != nil || response.Version != javaProjectProtocol || !validJavaSessionID(response.SessionID) {
		return nil, fmt.Errorf("Java project session response violates %s", javaProjectProtocol)
	}
	return &javaProjectSession{client, endpoint + "/" + url.PathEscape(response.SessionID), request, len(files)}, nil
}

func validJavaSessionID(id string) bool {
	if len(id) < 16 || len(id) > 64 {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c == '-') {
			return false
		}
	}
	return true
}

func (session *javaProjectSession) upload(ctx context.Context, files []checkerSource) error {
	_, err := javaProjectCall(ctx, session.client, http.MethodPut, session.endpoint+"/files", struct {
		Files []checkerSource `json:"files"`
	}{files})
	if errors.Is(err, errJavaRequestLimit) && len(files) > 1 {
		middle := len(files) / 2
		if err := session.upload(ctx, files[:middle]); err != nil {
			return err
		}
		return session.upload(ctx, files[middle:])
	}
	return err
}

func (session *javaProjectSession) analyze(ctx context.Context) (checkerResponse, error) {
	body, err := javaProjectCall(ctx, session.client, http.MethodPost, session.endpoint+"/analyze", nil)
	if err != nil {
		return checkerResponse{}, err
	}
	result, err := decodeCheckerResponse(body, session.request)
	if err != nil {
		return checkerResponse{}, err
	}
	if result.Coverage == nil {
		return checkerResponse{}, fmt.Errorf("Java project result has no coverage statistics")
	}
	if result.Coverage.TotalFiles != session.expectedFiles {
		return checkerResponse{}, fmt.Errorf("Java project coverage does not match its pinned manifest")
	}
	if result.Status == "complete" && (result.Coverage.FailedFiles != 0 || result.Coverage.AnalyzedFiles != result.Coverage.ParsedFiles || result.FindingsTruncated || result.DiagnosticsTruncated) {
		return checkerResponse{}, fmt.Errorf("Java project falsely claims complete coverage")
	}
	return result, nil
}

func (session *javaProjectSession) close() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = javaProjectCall(ctx, session.client, http.MethodDelete, session.endpoint, nil)
}

func javaProjectCall(ctx context.Context, client *http.Client, method, endpoint string, payload any) ([]byte, error) {
	var encoded []byte
	if payload != nil {
		var body bytes.Buffer
		encoder := json.NewEncoder(&body)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(payload); err != nil {
			return nil, err
		}
		if body.Len() > 64<<20 {
			return nil, errJavaRequestLimit
		}
		encoded = body.Bytes()
	}
	busyUntil := time.Now().Add(4 * time.Minute)
	for {
		var reader io.Reader
		if encoded != nil {
			reader = bytes.NewReader(encoded)
		}
		request, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
		if err != nil {
			return nil, err
		}
		request.Header.Set("Content-Type", "application/json")
		bounded := *client
		bounded.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		response, err := bounded.Do(request)
		if err != nil {
			return nil, job.Retryable(fmt.Errorf("Java project checker unavailable: %w", err), 15*time.Second)
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, checkerResponseBytes+1))
		_ = response.Body.Close()
		if err != nil || len(body) > checkerResponseBytes {
			return nil, fmt.Errorf("Java project response exceeds the supported size or cannot be read")
		}
		if response.StatusCode == http.StatusRequestEntityTooLarge {
			return nil, errJavaProjectLimit
		}
		if response.StatusCode == http.StatusTooManyRequests && time.Now().Before(busyUntil) {
			// The checker returns 429 before mutating a session. Retain the same
			// manifest/upload while the shared source/bytecode slot is occupied.
			timer := time.NewTimer(2 * time.Second)
			select {
			case <-timer.C:
				continue
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			}
		}
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			err := fmt.Errorf("Java project checker returned HTTP %d: %s", response.StatusCode, truncate(string(body), 1024))
			if response.StatusCode == 408 || response.StatusCode == 429 || response.StatusCode >= 500 {
				return nil, job.Retryable(err, 15*time.Second)
			}
			return nil, err
		}
		return body, nil
	}
}

func (coverage checkerCoverage) valid() bool {
	return coverage.TotalFiles >= 0 && coverage.TotalFiles <= storage.MaxJVMSourceFiles &&
		coverage.ParsedFiles >= 0 && coverage.FailedFiles >= 0 && coverage.AnalyzedFiles >= 0 &&
		coverage.ParsedFiles+coverage.FailedFiles == coverage.TotalFiles && coverage.AnalyzedFiles <= coverage.ParsedFiles &&
		coverage.TotalMethods >= 0 && coverage.AnalyzedMethods >= 0 && coverage.AnalyzedMethods <= coverage.TotalMethods && coverage.UnresolvedCalls >= 0
}

// Secondary source locations are evidence, too: a valid primary finding must
// never acquire a fabricated navigation target from an untrusted checker.
func verifyJavaNullnessTrace(evidence map[string]any, sources map[string]checkerSourceEvidence) bool {
	if evidence == nil || evidence["nullnessTrace"] == nil {
		return true
	}
	encoded, err := json.Marshal(evidence["nullnessTrace"])
	var steps []struct {
		Path    string `json:"path"`
		Line    int    `json:"line"`
		Column  int    `json:"column"`
		Kind    string `json:"kind"`
		Message string `json:"message"`
	}
	if err != nil || json.Unmarshal(encoded, &steps) != nil || len(steps) > 32 {
		delete(evidence, "nullnessTrace")
		evidence["traceIncomplete"] = true
		return false
	}
	verified := make([]map[string]any, 0, len(steps))
	for _, step := range steps {
		cleaned, err := storage.CleanRelativePath(step.Path)
		source, found := sources[cleaned]
		if err != nil || !found || step.Line < 1 || step.Line > len(source.lines) || step.Column < 1 || len(step.Kind) > 128 || len(step.Message) > 4096 {
			continue
		}
		if _, valid := utf16FindingEndColumn(source.lines[step.Line-1], step.Column); !valid {
			continue
		}
		verified = append(verified, map[string]any{"path": cleaned, "line": step.Line, "column": step.Column, "kind": step.Kind, "message": step.Message})
	}
	evidence["nullnessTrace"] = verified
	if len(verified) != len(steps) {
		evidence["traceIncomplete"] = true
		return false
	}
	return true
}

func javaAnalysisSummary(manifest storage.Manifest, responses []checkerResponse, diagnostics []string, bytecode spotBugsResponse, pipelinePartial bool) map[string]any {
	total := 0
	for _, file := range manifest.Files {
		if file.Language == "java" {
			total++
		}
	}
	coverage := checkerCoverage{}
	known := len(responses) > 0
	sourcePartial, findingsTruncated, diagnosticsTruncated := manifest.Quality != "source", false, false
	details := make([]checkerDiagnostic, 0, len(diagnostics))
	seen := map[string]bool{}
	bytecodeMessages := map[string]bool{}
	for _, message := range bytecode.Diagnostics {
		bytecodeMessages[message] = true
	}
	for _, response := range responses {
		sourcePartial = sourcePartial || response.Status == "partial"
		findingsTruncated = findingsTruncated || response.FindingsTruncated
		diagnosticsTruncated = diagnosticsTruncated || response.DiagnosticsTruncated
		if response.Coverage == nil {
			known = false
		} else {
			c := response.Coverage
			coverage.TotalFiles += c.TotalFiles
			coverage.ParsedFiles += c.ParsedFiles
			coverage.FailedFiles += c.FailedFiles
			coverage.AnalyzedFiles += c.AnalyzedFiles
			coverage.TotalMethods += c.TotalMethods
			coverage.AnalyzedMethods += c.AnalyzedMethods
			coverage.UnresolvedCalls += c.UnresolvedCalls
		}
		for _, detail := range response.DiagnosticDetails {
			details = append(details, detail)
			seen[detail.Message] = true
			seen[detail.Path+": "+detail.Message] = true
			seen[fmt.Sprintf("%s:%d: %s", detail.Path, detail.Line, detail.Message)] = true
		}
	}
	for _, message := range diagnostics {
		if strings.HasPrefix(message, "JAVA_FINDING_LIMIT:") {
			findingsTruncated = true
		}
		if seen[message] {
			continue
		}
		code := "SOURCE_DIAGNOSTIC"
		if strings.HasPrefix(message, "SpotBugs") || bytecodeMessages[message] {
			code = "BYTECODE_DIAGNOSTIC"
		} else {
			sourcePartial = true
		}
		details = append(details, checkerDiagnostic{Code: code, Message: message})
		seen[message] = true
	}
	var coverageValue any
	if known {
		missing := total - coverage.TotalFiles
		if missing > 0 {
			coverage.TotalFiles = total
			coverage.FailedFiles += missing
			sourcePartial = true
		}
		coverageValue = coverage
	}
	if len(details) > 1000 {
		details = details[:1000]
		diagnosticsTruncated = true
	}
	sourceStatus := "complete"
	if sourcePartial {
		sourceStatus = "partial"
	}
	bytecodeStatus := bytecode.Status
	if bytecodeStatus == "" {
		bytecodeStatus = "not_requested"
	}
	if pipelinePartial && sourceStatus == "complete" && bytecodeStatus != "partial" && bytecodeStatus != "skipped" {
		sourceStatus = "partial"
	}
	summary := map[string]any{
		"version": "java-analysis-summary-v1", "coverage": coverageValue,
		"diagnosticCount": len(diagnostics), "diagnostics": details,
		"diagnosticsTruncated": diagnosticsTruncated, "findingsTruncated": findingsTruncated,
		"engines": map[string]any{"source": map[string]any{"name": "java-checker", "status": sourceStatus},
			"bytecode": map[string]any{"status": bytecodeStatus, "reason": bytecode.SkipReason}},
	}
	// Keep optional archive provenance versioned with the immutable source manifest.
	if encoded, err := json.Marshal(manifest); err == nil {
		var fields map[string]json.RawMessage
		if json.Unmarshal(encoded, &fields) == nil && fields["jvmArchive"] != nil {
			summary["scope"] = fields["jvmArchive"]
		}
	}
	return summary
}
