package app

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHTMLReportIncludesStableSourceLocatorAndEscapesContent(t *testing.T) {
	runs := []map[string]any{{"kind": "java_sast", "status": "complete", "toolName": "java-checker"}}
	findings := []map[string]any{{
		"severity": "high", "ruleId": "JAVA001", "title": "Runtime <exec>",
		"message": "message", "path": "src/Foo.java", "startLine": 12, "startColumn": 5,
		"endLine": 13, "endColumn": 9,
		"sourceProjectId": "project-1", "sourceFileId": "file-1", "snippet": "Runtime.exec(value < 1);",
	}}
	snapshot := map[string]any{
		"schema": reportSchemaVersion, "generatedAt": "2026-08-26T10:00:00+08:00",
		"task":    map[string]any{"id": "task-1", "displayName": "unsafe <name>", "inputSha256": "abc"},
		"summary": buildReportSummary(runs, findings), "runs": runs, "findings": findings,
		"findingsTruncated": false,
	}
	body := string(buildHTMLReport(snapshot))
	for _, expected := range []string{
		"binaryscan-report-v3", "执行摘要", "检测运行（1）", "漏洞明细（1）", "src/Foo.java:12:5",
		"unsafe &lt;name&gt;", "Runtime &lt;exec&gt;", "value &lt; 1",
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("report omitted %q: %s", expected, body)
		}
	}
	if strings.Contains(body, "unsafe <name>") || strings.Contains(body, "Runtime <exec>") {
		t.Fatal("report contains unescaped content")
	}
	for _, forbidden := range []string{"在源码中打开", "href=\"/tasks/", "file:///tasks/"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("offline report retained unusable source link %q", forbidden)
		}
	}
}

func TestReportSummaryCountsSeverityFilesRulesAndRuns(t *testing.T) {
	summary := buildReportSummary(
		[]map[string]any{{"status": "complete"}, {"status": "partial"}, {"status": "future"}},
		[]map[string]any{
			{"severity": "high", "path": "a.c", "ruleId": "C001"},
			{"severity": "HIGH", "path": "a.c", "ruleId": "C001"},
			{"severity": "unexpected", "path": "b.c", "ruleId": "C002"},
		},
	)
	if summary["findingCount"] != 3 || summary["affectedFileCount"] != 2 || summary["ruleCount"] != 2 {
		t.Fatalf("unexpected report summary: %#v", summary)
	}
	severity := reportMap(summary["severityCounts"])
	if severity["high"] != 2 || severity["unknown"] != 1 {
		t.Fatalf("unexpected severity counts: %#v", severity)
	}
	runCounts := reportMap(summary["runCounts"])
	if runCounts["total"] != 3 || runCounts["complete"] != 1 || runCounts["partial"] != 1 || runCounts["other"] != 1 {
		t.Fatalf("unexpected run counts: %#v", runCounts)
	}
}

func TestDOCXReportContainsStructuredSections(t *testing.T) {
	findings := []map[string]any{{
		"severity": "high", "ruleId": "C001", "title": "unsafe <copy>", "message": "buffer copy",
		"path": "src/main.c", "startLine": 8, "startColumn": 3, "snippet": "strcpy(dst, src);",
	}}
	snapshot := map[string]any{
		"schema": reportSchemaVersion, "generatedAt": "2026-08-26T10:00:00+08:00",
		"task":    map[string]any{"id": "task-1", "displayName": "sample", "inputSha256": "abc"},
		"summary": buildReportSummary(nil, findings), "runs": []map[string]any{}, "findings": findings,
	}
	body, err := buildDOCXReport(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if output := os.Getenv("BINARYSCAN_DOCX_QA_OUTPUT"); output != "" {
		if err := os.WriteFile(output, body, 0o600); err != nil {
			t.Fatalf("write DOCX QA artifact: %v", err)
		}
	}
	archive, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatalf("open generated docx: %v", err)
	}
	parts := make(map[string]string)
	for _, file := range archive.File {
		reader, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		content, err := io.ReadAll(reader)
		reader.Close()
		if err != nil {
			t.Fatal(err)
		}
		parts[file.Name] = string(content)
	}
	for _, required := range []string{"word/document.xml", "word/styles.xml", "word/header1.xml", "word/footer1.xml"} {
		if parts[required] == "" {
			t.Errorf("generated docx omitted %s", required)
		}
	}
	document := parts["word/document.xml"]
	for _, expected := range []string{"执行摘要", "任务信息", "检测运行", "漏洞明细", "src/main.c:8:3", "unsafe &lt;copy&gt;", `<w:tbl>`} {
		if !strings.Contains(document, expected) {
			t.Errorf("document.xml omitted %q", expected)
		}
	}
	if strings.Contains(document, `&quot;schema&quot;`) {
		t.Fatal("DOCX still renders raw JSON instead of a structured report")
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
	body := []byte(`{"schema":"binaryscan-report-v3"}`)
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
