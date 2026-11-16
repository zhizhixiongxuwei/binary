package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"binaryscan.local/backend/internal/checkrules"
	"binaryscan.local/backend/internal/storage"
)

func TestJavaProjectKeepsOneContextAcrossUploadBatches(t *testing.T) {
	const sessionID = "1234567890abcdef1234567890abcdef"
	manifest := storage.Manifest{Quality: "source", Files: make([]storage.ManifestFile, 201)}
	for i := range manifest.Files {
		manifest.Files[i] = storage.ManifestFile{Path: fmt.Sprintf("example/Class%d.java", i), Language: "java", SHA256: strings.Repeat("a", 64), SizeBytes: 20}
	}
	uploaded, deleted := 0, false
	catalog := checkrules.Catalog{Version: "checker-v1", Language: "java", CatalogVersion: "sha256:" + strings.Repeat("b", 64), Rules: []checkrules.Rule{{ID: javaNullDereferenceRuleID, Name: "Null dereference", Language: "java"}}}
	selection, err := checkrules.Select(catalog, []string{javaNullDereferenceRuleID}, catalog.CatalogVersion, false)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("immutable manifest"))
	project := checkerProject{id: "project", language: "java", manifestSHA256: digest[:], selection: selection}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v2/java/projects":
			var payload struct {
				ProjectID, RunID, ManifestSHA256, CatalogVersion string
				Files                                            []javaProjectFile
				RuleIDs                                          []string
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Error(err)
			}
			if payload.ProjectID != "project" || payload.RunID != "run" || payload.ManifestSHA256 != fmt.Sprintf("%x", digest) || payload.CatalogVersion != catalog.CatalogVersion || len(payload.Files) != 201 || len(payload.RuleIDs) != 1 {
				t.Errorf("unbound or incomplete context: %+v", payload)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"version": javaProjectProtocol, "sessionId": sessionID})
		case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/files"):
			var payload struct{ Files []checkerSource }
			_ = json.NewDecoder(r.Body).Decode(&payload)
			uploaded += len(payload.Files)
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/analyze"):
			if uploaded != 201 {
				t.Errorf("analyzed incomplete upload: %d", uploaded)
			}
			_ = json.NewEncoder(w).Encode(checkerResponse{Version: "checker-v1", ProjectID: "project", Status: "complete", Findings: []checkerFinding{}, Diagnostics: []string{}, CatalogVersion: catalog.CatalogVersion, AppliedRuleIDs: []string{javaNullDereferenceRuleID}, Coverage: &checkerCoverage{TotalFiles: 201, ParsedFiles: 201, AnalyzedFiles: 201}})
		case r.Method == http.MethodDelete:
			deleted = true
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	session, err := createJavaProject(context.Background(), server.Client(), server.URL+"/v1/check", project, manifest, "run")
	if err != nil {
		t.Fatal(err)
	}
	for _, count := range []int{200, 1} {
		if err := session.upload(context.Background(), make([]checkerSource, count)); err != nil {
			t.Fatal(err)
		}
	}
	result, err := session.analyze(context.Background())
	if err != nil || result.Coverage.TotalFiles != 201 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	session.close()
	if !deleted {
		t.Fatal("project context was not released")
	}
}

func TestJavaProjectRejectsUnboundOrIncompleteResult(t *testing.T) {
	result := checkerResponse{Version: "checker-v1", ProjectID: "other-project", Status: "complete"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(result) }))
	defer server.Close()
	session := javaProjectSession{client: server.Client(), endpoint: server.URL, request: checkerRequest{ProjectID: "expected"}}
	if _, err := session.analyze(context.Background()); err == nil {
		t.Fatal("accepted result belonging to another project")
	}
	result.ProjectID = "expected"
	if _, err := session.analyze(context.Background()); err == nil {
		t.Fatal("accepted project result without coverage")
	}
	result.Coverage = &checkerCoverage{TotalFiles: 2, ParsedFiles: 2, FailedFiles: 1}
	if _, err := session.analyze(context.Background()); err == nil {
		t.Fatal("accepted contradictory coverage")
	}
	result.Coverage = &checkerCoverage{}
	session.expectedFiles = 2
	if _, err := session.analyze(context.Background()); err == nil {
		t.Fatal("accepted empty coverage for a nonempty pinned project")
	}
	result.Coverage = &checkerCoverage{TotalFiles: 2, ParsedFiles: 1, FailedFiles: 1, AnalyzedFiles: 1}
	if _, err := session.analyze(context.Background()); err == nil {
		t.Fatal("accepted incomplete source while claiming complete")
	}
}

func TestJavaProjectLimitHasExplicitDegradationSignal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusRequestEntityTooLarge) }))
	defer server.Close()
	_, err := javaProjectCall(context.Background(), server.Client(), http.MethodPost, server.URL, nil)
	if !errors.Is(err, errJavaProjectLimit) {
		t.Fatalf("input-limit error=%v", err)
	}
}

func TestJavaSummaryPreservesRealCoverageAndRequestedEngineSkip(t *testing.T) {
	manifest := storage.Manifest{Quality: "source", Files: []storage.ManifestFile{{Language: "java"}, {Language: "java"}}}
	responses := []checkerResponse{{Status: "partial", Coverage: &checkerCoverage{TotalFiles: 2, ParsedFiles: 1, FailedFiles: 1, AnalyzedFiles: 1}}}
	summary := javaAnalysisSummary(manifest, responses, []string{"bad.java: parse failure", "SpotBugs skipped: input limit"}, spotBugsResponse{Status: "skipped", SkipReason: "input_too_large"}, true)
	coverage := summary["coverage"].(checkerCoverage)
	if coverage.ParsedFiles != 1 || coverage.FailedFiles != 1 || summary["diagnosticCount"] != 2 {
		t.Fatalf("invented coverage: %+v", summary)
	}
	engines := summary["engines"].(map[string]any)
	if engines["bytecode"].(map[string]any)["status"] != "skipped" {
		t.Fatal("lost requested bytecode skip")
	}
	unknown := javaAnalysisSummary(manifest, nil, nil, spotBugsResponse{}, false)
	if unknown["coverage"] != nil {
		t.Fatal("invented coverage for result without statistics")
	}
	if unknown["engines"].(map[string]any)["bytecode"].(map[string]any)["status"] != "not_requested" {
		t.Fatal("unrequested engine misreported as failed")
	}
	degraded := javaAnalysisSummary(manifest, []checkerResponse{{Status: "complete", Coverage: &checkerCoverage{TotalFiles: 2, ParsedFiles: 2, AnalyzedFiles: 2}}}, []string{"JAVA_FINDING_LIMIT: findings exceeded the run finding limit"}, spotBugsResponse{}, true)
	if degraded["findingsTruncated"] != true || degraded["engines"].(map[string]any)["source"].(map[string]any)["status"] != "partial" {
		t.Fatal("pipeline truncation was hidden behind complete engine results")
	}
}

func TestJavaTraceCannotNavigateOutsideVerifiedSource(t *testing.T) {
	sources := map[string]checkerSourceEvidence{"example/Demo.java": {lines: []string{"void run() { sink(); }"}}}
	evidence := map[string]any{"nullnessTrace": []map[string]any{
		{"path": "example/Demo.java", "line": 1, "column": 1, "kind": "sink", "message": "dereference"},
		{"path": "../../secret.java", "line": 1, "column": 1, "kind": "argument", "message": "untrusted"},
		{"path": "example/Demo.java", "line": 200, "column": 1, "kind": "argument", "message": "wrong line"},
	}}
	if verifyJavaNullnessTrace(evidence, sources) {
		t.Fatal("unverified secondary location accepted")
	}
	if len(evidence["nullnessTrace"].([]map[string]any)) != 1 || evidence["traceIncomplete"] != true {
		t.Fatalf("valid primary evidence was lost: %+v", evidence)
	}
}

func TestJavaUploadSplitsWorstCaseEscapingWithinWireBudget(t *testing.T) {
	requests := 0
	var received int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.ContentLength > 64<<20 {
			t.Errorf("oversized upload reached server: %d", r.ContentLength)
		}
		count, err := io.Copy(io.Discard, r.Body)
		if err != nil {
			t.Error(err)
		}
		received += count
		w.WriteHeader(204)
	}))
	defer server.Close()
	content := strings.Repeat("\"", 4<<20)
	files := make([]checkerSource, 8)
	for i := range files {
		files[i] = checkerSource{Path: fmt.Sprintf("file%d.java", i), Content: content}
	}
	session := javaProjectSession{client: server.Client(), endpoint: server.URL}
	if err := session.upload(context.Background(), files); err != nil {
		t.Fatal(err)
	}
	if requests != 2 || received < 64<<20 {
		t.Fatalf("split lost source bytes: requests=%d received=%d", requests, received)
	}
}

func TestJavaBusyRetriesSameUploadWithoutConsumingJobAttempts(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "kept-source") {
			t.Error("retry lost pinned payload")
		}
		if attempts == 1 {
			w.WriteHeader(429)
			return
		}
		w.WriteHeader(204)
	}))
	defer server.Close()
	if _, err := javaProjectCall(context.Background(), server.Client(), http.MethodPut, server.URL, map[string]string{"content": "kept-source"}); err != nil {
		t.Fatal(err)
	}
	if attempts != 2 {
		t.Fatalf("attempts=%d", attempts)
	}
}

func TestJavaBusyWaitHonorsCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(429) }))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	_, err := javaProjectCall(ctx, server.Client(), http.MethodPost, server.URL, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancelled wait=%v", err)
	}
}
