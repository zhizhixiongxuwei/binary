package scanner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"binaryscan.local/backend/internal/checkrules"
	"binaryscan.local/backend/internal/config"
	"binaryscan.local/backend/internal/storage"
)

func TestSpotBugsOnlyRunsForSelectedJVMBinaries(t *testing.T) {
	project := checkerProject{
		language: "java", sourceKind: "jvm",
		input: spotBugsInput{detectedFormat: sql.NullString{String: "jar", Valid: true}},
	}
	if got := project.spotBugsFormat(); got != "jar" {
		t.Fatalf("legacy Java selection = %q, want jar", got)
	}
	project.selection = &checkrules.Selection{EnabledRuleIDs: []string{"java-weak-cipher"}}
	if got := project.spotBugsFormat(); got != "" {
		t.Fatalf("unselected Java null rule requested %q", got)
	}
	project.selection.EnabledRuleIDs = []string{javaNullDereferenceRuleID}
	for detected, expected := range map[string]string{
		"jar": "jar", "class": "class", "java-class": "class", "apk": "", "dex": "",
	} {
		project.input.detectedFormat.String = detected
		if got := project.spotBugsFormat(); got != expected {
			t.Errorf("format %q = %q, want %q", detected, got, expected)
		}
	}
	project.input.detectedFormat.String = "jar"
	project.language = "c"
	if got := project.spotBugsFormat(); got != "" {
		t.Fatalf("non-Java selection requested %q", got)
	}
}

func TestSpotBugsSkipsLargeJarWithoutCallingChecker(t *testing.T) {
	root := t.TempDir()
	key := "blob.jar"
	filename := filepath.Join(root, key)
	if err := os.WriteFile(filename, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(filename, spotBugsInputLimit+1); err != nil {
		t.Fatal(err)
	}
	executor := Executor{cfg: config.Config{Worker: config.Worker{BlobRoot: root}}}
	digest := sha256.Sum256([]byte("identity from the original project"))
	input := spotBugsInput{
		blobID:      sql.NullString{String: "blob-id", Valid: true},
		logicalPath: sql.NullString{String: "Probe.jar", Valid: true},
		storageKey:  sql.NullString{String: key, Valid: true},
		sizeBytes:   sql.NullInt64{Int64: spotBugsInputLimit + 1, Valid: true},
		sha256:      digest[:],
	}
	manifest := storage.Manifest{InputBlobID: input.blobID.String, InputSHA256: hex.EncodeToString(digest[:])}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("SpotBugs endpoint called for skipped or invalid input")
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	result := executor.checkSpotBugs(context.Background(), server.Client(), server.URL, input, manifest, "jar", checkerFindingLimit)
	if result.Status != "skipped" || result.SkipReason != "input_too_large" || len(result.Findings) != 0 || len(result.Diagnostics) != 1 {
		t.Fatalf("large JAR did not report the size-based skip: %+v", result)
	}
	result = executor.checkSpotBugs(context.Background(), server.Client(), server.URL, input, manifest, "class", checkerFindingLimit)
	if result.Status != "partial" || result.SkipReason != "" {
		t.Fatalf("oversized class did not retain invalid-input semantics: %+v", result)
	}
	input.sizeBytes.Int64++
	result = executor.checkSpotBugs(context.Background(), server.Client(), server.URL, input, manifest, "jar", checkerFindingLimit)
	if result.Status != "partial" || result.SkipReason != "" || !strings.Contains(strings.Join(result.Diagnostics, " "), "size does not match") {
		t.Fatalf("invalid blob size was mistaken for a valid skip: %+v", result)
	}
	manifest.InputBlobID = "different-id"
	result = executor.checkSpotBugs(context.Background(), server.Client(), server.URL, input, manifest, "jar", checkerFindingLimit)
	if result.Status != "partial" || result.SkipReason != "" || !strings.Contains(strings.Join(result.Diagnostics, " "), "identity") {
		t.Fatalf("invalid blob identity was mistaken for a valid skip: %+v", result)
	}
}

func TestSpotBugsRetriesBusyEngineAndPreservesBytecodeCoordinates(t *testing.T) {
	root := t.TempDir()
	body := []byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 65}
	digest := sha256.Sum256(body)
	key := "blob.class"
	if err := os.WriteFile(filepath.Join(root, key), body, 0o600); err != nil {
		t.Fatal(err)
	}
	executor := Executor{cfg: config.Config{Worker: config.Worker{BlobRoot: root}}}
	input := spotBugsInput{
		blobID:      sql.NullString{String: "blob-id", Valid: true},
		logicalPath: sql.NullString{String: "example/Probe.class", Valid: true},
		storageKey:  sql.NullString{String: key, Valid: true},
		sizeBytes:   sql.NullInt64{Int64: int64(len(body)), Valid: true},
		sha256:      digest[:],
	}
	manifest := storage.Manifest{InputBlobID: input.blobID.String, InputSHA256: hex.EncodeToString(digest[:])}
	zero := 0
	valid := spotBugsFinding{
		Pattern: "NP_ALWAYS_NULL", ClassName: "example.Probe", MethodName: "run", MethodDescriptor: "()I",
		SourcePath: "example/Probe.java", BytecodeOffset: &zero, Message: "Null pointer dereference", Priority: 1,
	}
	invalid := valid
	invalid.Pattern = "NP_OPTIONAL_RETURN_NULL"
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt := calls.Add(1)
		got, err := io.ReadAll(r.Body)
		if err != nil || !bytes.Equal(got, body) || r.ContentLength != int64(len(body)) {
			t.Errorf("unexpected binary body: %x, length %d, error %v", got, r.ContentLength, err)
		}
		if r.Method != http.MethodPost || r.URL.Path != "/v1/bytecode/check" ||
			r.URL.Query().Get("format") != "class" || r.Header.Get("Content-Type") != "application/octet-stream" {
			t.Errorf("unexpected bytecode request: %s %s %q", r.Method, r.URL, r.Header.Get("Content-Type"))
		}
		if attempt == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_ = json.NewEncoder(w).Encode(spotBugsResponse{
			Version: spotBugsProtocol, Status: "complete", ToolVersion: spotBugsVersion,
			Findings: []spotBugsFinding{valid}, Diagnostics: []string{},
		})
	}))
	defer server.Close()

	result := executor.checkSpotBugs(context.Background(), server.Client(), server.URL+"/v1/check", input, manifest, "class", checkerFindingLimit)
	if result.Status != "complete" || len(result.Findings) != 1 || len(result.Diagnostics) != 0 || calls.Load() != 2 {
		t.Fatalf("busy bytecode checker was not retried successfully: %+v, calls=%d", result, calls.Load())
	}
	result.Findings = append(result.Findings, invalid)
	result.validateFindings(checkerFindingLimit)
	if result.Status != "partial" || len(result.Findings) != 1 || len(result.Diagnostics) != 1 ||
		!strings.Contains(result.Diagnostics[0], "invalid bytecode findings") {
		t.Fatalf("unexpected result: %+v", result)
	}
	evidence := result.Findings[0].evidence(result.ToolVersion)
	if evidence["engine"] != "spotbugs" || evidence["locationKind"] != "bytecode" || evidence["bytecodeOffset"] != 0 ||
		evidence["sourcePath"] != valid.SourcePath || evidence["originalLine"] != nil {
		t.Fatalf("unexpected evidence: %+v", evidence)
	}

	if err := os.WriteFile(filepath.Join(root, key), bytes.Repeat([]byte{0}, len(body)), 0o600); err != nil {
		t.Fatal(err)
	}
	result = executor.checkSpotBugs(context.Background(), server.Client(), server.URL+"/v1/check", input, manifest, "class", checkerFindingLimit)
	if result.Status != "partial" || len(result.Findings) != 0 || len(result.Diagnostics) != 1 ||
		!strings.Contains(result.Diagnostics[0], "digest") || calls.Load() != 2 {
		t.Fatalf("corrupt input was not blocked: %+v, calls=%d", result, calls.Load())
	}
}

func TestSpotBugsRejectsUnavailableOrWrongVersionEngine(t *testing.T) {
	for _, response := range []struct {
		name string
		code int
		body string
	}{
		{"unavailable", http.StatusServiceUnavailable, ""},
		{"wrong version", http.StatusOK, `{"version":"spotbugs-v1","status":"complete","toolVersion":"4.9.0","findings":[],"diagnostics":[]}`},
	} {
		t.Run(response.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(response.code)
				_, _ = io.WriteString(w, response.body)
			}))
			defer server.Close()
			if _, err := callSpotBugs(context.Background(), server.Client(), server.URL, "jar", []byte("input")); err == nil {
				t.Fatal("expected the bytecode stage to fail validation")
			}
		})
	}
}
