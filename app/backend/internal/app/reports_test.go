package app

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
	"html"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHTMLReportIncludesStableSourceLocatorAndEscapesContent(t *testing.T) {
	snapshot := map[string]any{
		"task": map[string]any{"id": "task-1", "displayName": "unsafe <name>", "inputSha256": "abc"},
		"findings": []map[string]any{{
			"severity": "high", "ruleId": "JAVA001", "title": "Runtime <exec>",
			"message": "message", "path": "src/Foo.java", "startLine": 12, "startColumn": 5,
			"endLine": 13, "endColumn": 9,
			"sourceProjectId": "project-1", "sourceFileId": "file-1", "snippet": "Runtime.exec(value < 1);",
		}},
		"findingsTruncated": false,
	}
	body := string(buildHTMLReport(snapshot))
	href := reportSourceHref("task-1", snapshot["findings"].([]map[string]any)[0])
	for _, expected := range []string{
		"binaryscan-report-v2", "src/Foo.java:12:5",
		html.EscapeString(href),
		"unsafe &lt;name&gt;", "Runtime &lt;exec&gt;", "value &lt; 1",
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("report omitted %q: %s", expected, body)
		}
	}
	if strings.Contains(body, "unsafe <name>") || strings.Contains(body, "Runtime <exec>") {
		t.Fatal("report contains unescaped content")
	}
	parsed, err := url.Parse(href)
	if err != nil {
		t.Fatalf("parse report source URL: %v", err)
	}
	if parsed.Path != "/tasks/task-1" {
		t.Fatalf("source URL path = %q", parsed.Path)
	}
	wantQuery := map[string]string{
		"detail": "results", "result": "decompile", "sourceProject": "project-1",
		"sourceFile": "file-1", "sourcePath": "src/Foo.java", "startLine": "12",
		"startColumn": "5", "endLine": "13", "endColumn": "9",
	}
	for key, expected := range wantQuery {
		if actual := parsed.Query().Get(key); actual != expected {
			t.Errorf("source URL query %s = %q, want %q", key, actual, expected)
		}
	}
	for _, legacy := range []string{"tab", "project", "file", "line", "column"} {
		if parsed.Query().Has(legacy) {
			t.Errorf("source URL retained legacy query %q", legacy)
		}
	}
}

func TestReportSourceHrefUsesOneBasedFallbackRange(t *testing.T) {
	href := reportSourceHref("task-1", map[string]any{
		"sourceProjectId": "project-1", "sourceFileId": "file-1",
		"startLine": 0, "startColumn": nil, "endLine": -1, "endColumn": 0,
	})
	parsed, err := url.Parse(href)
	if err != nil {
		t.Fatal(err)
	}
	for key, expected := range map[string]string{
		"startLine": "1", "startColumn": "1", "endLine": "1", "endColumn": "2",
	} {
		if actual := parsed.Query().Get(key); actual != expected {
			t.Errorf("%s = %q, want %q", key, actual, expected)
		}
	}
}

func TestReportIntentMatchesCanonicalRunSet(t *testing.T) {
	stored := storedReport{
		Record: reportRecord{Format: "html"},
		RunIDs: []string{"run-b", "run-a"},
	}
	if !reportIntentMatches(stored, reportRequest{Format: "html", RunIDs: []string{"run-a", "run-b"}}) {
		t.Fatal("equivalent run selection did not replay idempotently")
	}
	for _, request := range []reportRequest{
		{Format: "json", RunIDs: []string{"run-a", "run-b"}},
		{Format: "html", RunIDs: []string{"run-a"}},
		{Format: "html", RunIDs: []string{"run-a", "run-c"}},
	} {
		if reportIntentMatches(stored, request) {
			t.Fatalf("conflicting request matched: %#v", request)
		}
	}
	stored.Deleted = true
	if reportIntentMatches(stored, reportRequest{Format: "html", RunIDs: []string{"run-a", "run-b"}}) {
		t.Fatal("deleted report replayed as an active idempotent result")
	}
}

func TestVerifyReportFileChecksSizeAndDigest(t *testing.T) {
	t.Parallel()
	filename := filepath.Join(t.TempDir(), "report.json")
	body := []byte(`{"schema":"binaryscan-report-v2"}`)
	if err := os.WriteFile(filename, body, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	expectedSize := sql.NullInt64{Int64: int64(len(body)), Valid: true}
	expectedSHA := sql.NullString{String: fmt.Sprintf("%x", digest), Valid: true}
	if err := verifyReportFile(filename, expectedSize, expectedSHA); err != nil {
		t.Fatalf("verify valid report: %v", err)
	}
	expectedSize.Int64++
	if err := verifyReportFile(filename, expectedSize, expectedSHA); err == nil {
		t.Fatal("expected size mismatch")
	}
	expectedSize.Int64--
	expectedSHA.String = strings.Repeat("0", 64)
	if err := verifyReportFile(filename, expectedSize, expectedSHA); err == nil {
		t.Fatal("expected digest mismatch")
	}
}
