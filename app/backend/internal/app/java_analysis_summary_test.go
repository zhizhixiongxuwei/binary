package app

import (
	"strings"
	"testing"
)

func TestLegacyJavaSummaryRestoresDiagnosticsWithoutInventingCoverage(t *testing.T) {
	body := []byte(`{"schema":"checker-evidence-v1","projectId":"p","language":"java","responses":[{"status":"partial"}],"diagnostics":["a/Foo.java: parser rejected decompiled source","SpotBugs skipped: too large"],"bytecodeResponse":{"status":"skipped","skipReason":"input_too_large"}}`)
	summary := legacyJavaAnalysisSummary(body, "p", 276)
	if summary == nil || summary["diagnosticCount"] != 2 {
		t.Fatalf("missing diagnostics: %#v", summary)
	}
	coverage := reportMap(summary["coverage"])
	if coverage["parsedFiles"] != nil || coverage["analyzedFiles"] != nil || coverage["failedFiles"] != 1 {
		t.Fatalf("invented coverage: %#v", coverage)
	}
	if legacyJavaAnalysisSummary(body, "other-project", 276) != nil {
		t.Fatal("accepted evidence for another project")
	}
	if !analysisRunIsPartial(map[string]any{"status": "complete", "analysisSummary": summary}) {
		t.Fatal("requested skipped engine must be partial")
	}
}

func TestJavaSummaryDoesNotDowngradeUnrequestedBytecode(t *testing.T) {
	run := map[string]any{"status": "complete", "analysisSummary": map[string]any{"engines": map[string]any{"source": map[string]any{"status": "complete"}, "bytecode": map[string]any{"status": "not_requested"}}}}
	if analysisRunIsPartial(run) {
		t.Fatal("unrequested engine must not downgrade result")
	}
	run["resultQuality"] = "partial_source"
	if reportRunStatus(run) != "partial" {
		t.Fatal("report ignored partial quality")
	}
	summary := buildReportSummary([]map[string]any{run}, nil)
	if reportMap(summary["runCounts"])["partial"] != 1 {
		t.Fatal("report count disagrees with run quality")
	}
}

func TestJavaReportIncludesCoverageDiagnosticsAndTrace(t *testing.T) {
	run := map[string]any{"kind": "java_check", "status": "complete", "analysisSummary": map[string]any{
		"coverage": map[string]any{"totalFiles": 276, "analyzedFiles": 204, "failedFiles": 72}, "diagnosticCount": 73,
		"engines":     map[string]any{"bytecode": map[string]any{"status": "skipped", "reason": "input_too_large"}},
		"diagnostics": []map[string]any{{"code": "PARSE_ERROR", "path": "Foo.java", "message": "unsupported <syntax>"}},
	}}
	finding := map[string]any{"evidence": map[string]any{"nullnessTrace": []map[string]any{{"kind": "nullable-source", "path": "Foo.java", "line": 12, "column": 3, "message": "query can return null"}}}}
	body := string(buildHTMLReport(map[string]any{"runs": []map[string]any{run}, "findings": []map[string]any{finding}}))
	for _, text := range []string{"已分析 204", "解析失败 72", "input_too_large", "unsupported &lt;syntax&gt;", "空值传播路径", "Foo.java:12:3"} {
		if !strings.Contains(body, text) {
			t.Fatalf("report missing %q", text)
		}
	}
	if !strings.Contains(reportJavaAnalysisText(map[string]any{}), "未知") {
		t.Fatal("missing history shown as complete")
	}
}
