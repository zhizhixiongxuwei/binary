package app

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"binaryscan.local/backend/internal/storage"
	"github.com/gin-gonic/gin"
)

const javaSummaryVersion = "java-analysis-summary-v1"

// Analysis summaries are immutable run evidence, not inferred from the number of
// findings. Missing historical counters stay null rather than becoming 100%.
func (s *taskService) javaAnalysisSummaries(ctx *gin.Context, taskID string) (map[string]any, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT a.run_id, r.subject_id, p.file_count,
		a.metadata, a.storage_key, a.size_bytes, HEX(a.sha256)
		FROM run_artifacts a JOIN runs r ON r.id=a.run_id AND r.task_id=a.task_id
		JOIN source_projects p ON p.id=r.subject_id AND p.task_id=r.task_id
		WHERE a.task_id=? AND r.kind='java_check' AND a.artifact_kind='checker-response-json'
		AND a.state='ready' AND a.deleted_at IS NULL ORDER BY a.created_at DESC LIMIT 100`, taskID)
	if err != nil {
		return nil, err
	}
	type record struct {
		runID, projectID, key string
		files, size           int64
		metadata              []byte
		sha                   sql.NullString
	}
	records := make([]record, 0)
	for rows.Next() {
		var row record
		if err := rows.Scan(&row.runID, &row.projectID, &row.files, &row.metadata, &row.key, &row.size, &row.sha); err != nil {
			rows.Close()
			return nil, err
		}
		records = append(records, row)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	result := make(map[string]any)
	legacyReads := 0
	for _, row := range records {
		var metadata map[string]json.RawMessage
		if len(row.metadata) <= 2<<20 && json.Unmarshal(row.metadata, &metadata) == nil {
			var summary map[string]any
			if json.Unmarshal(metadata["analysisSummary"], &summary) == nil && summary["version"] == javaSummaryVersion {
				result[row.runID] = summary
				continue
			}
		}
		// Recover old diagnostics only from bounded, verified evidence. The old
		// protocol did not record analyzed file counts, so those remain unknown.
		if legacyReads >= 10 || row.size <= 0 || row.size > 8<<20 || !row.sha.Valid {
			continue
		}
		key, err := storage.CleanRelativePath(row.key)
		if err != nil {
			continue
		}
		filename := filepath.Join(s.storageRoot, filepath.FromSlash(key))
		if verifyReportFile(filename, sql.NullInt64{Int64: row.size, Valid: true}, row.sha) != nil {
			continue
		}
		legacyReads++
		body, err := os.ReadFile(filename)
		if err != nil {
			continue
		}
		if summary := legacyJavaAnalysisSummary(body, row.projectID, row.files); summary != nil {
			result[row.runID] = summary
		}
	}
	return result, nil
}

func legacyJavaAnalysisSummary(body []byte, projectID string, total int64) map[string]any {
	var evidence struct {
		Schema      string   `json:"schema"`
		ProjectID   string   `json:"projectId"`
		Language    string   `json:"language"`
		Diagnostics []string `json:"diagnostics"`
		Responses   []struct {
			Status string `json:"status"`
		} `json:"responses"`
		Bytecode struct {
			Status     string `json:"status"`
			SkipReason string `json:"skipReason"`
		} `json:"bytecodeResponse"`
	}
	if json.Unmarshal(body, &evidence) != nil || evidence.Schema != "checker-evidence-v1" || evidence.ProjectID != projectID || evidence.Language != "java" || evidence.Diagnostics == nil || len(evidence.Responses) == 0 || len(evidence.Diagnostics) > 20000 {
		return nil
	}
	diagnostics := make([]map[string]any, 0)
	failed := make(map[string]bool)
	for _, diagnostic := range evidence.Diagnostics {
		item := map[string]any{"code": "LEGACY_DIAGNOSTIC", "message": diagnostic}
		if path, ok := strings.CutSuffix(diagnostic, ": parser rejected decompiled source"); ok {
			if _, err := storage.CleanRelativePath(path); err == nil {
				failed[path] = true
				item["path"] = path
				item["code"] = "SOURCE_REJECTED"
			}
		}
		if len(diagnostics) < 1000 {
			diagnostics = append(diagnostics, item)
		}
	}
	sourceStatus := "complete"
	for _, response := range evidence.Responses {
		if response.Status != "complete" {
			sourceStatus = "partial"
		}
	}
	bytecodeStatus := evidence.Bytecode.Status
	if bytecodeStatus == "" {
		bytecodeStatus = "unknown"
	}
	return map[string]any{
		"version": javaSummaryVersion, "historical": true,
		"coverage":        map[string]any{"totalFiles": total, "parsedFiles": nil, "analyzedFiles": nil, "failedFiles": len(failed), "totalMethods": nil, "analyzedMethods": nil, "unresolvedCalls": nil},
		"diagnosticCount": len(evidence.Diagnostics), "diagnostics": diagnostics,
		"diagnosticsTruncated": len(evidence.Diagnostics) > len(diagnostics), "findingsTruncated": false,
		"engines": map[string]any{"source": map[string]any{"status": sourceStatus, "name": "java-checker"}, "bytecode": map[string]any{"status": bytecodeStatus, "reason": evidence.Bytecode.SkipReason}},
	}
}

func analysisRunIsPartial(run map[string]any) bool {
	if run["status"] == "partial" || (run["status"] == "complete" && (run["resultQuality"] == "partial_source" || run["resultQuality"] == "bytecode_only")) {
		return true
	}
	summary := reportMap(run["analysisSummary"])
	engines := reportMap(summary["engines"])
	for _, name := range []string{"source", "bytecode"} {
		status := reportText(reportMap(engines[name])["status"])
		if status == "partial" || status == "skipped" || status == "failed" {
			return true
		}
	}
	return summary["findingsTruncated"] == true || summary["diagnosticsTruncated"] == true
}

func reportRunStatus(run map[string]any) string {
	if run["status"] == "complete" && analysisRunIsPartial(run) {
		return "partial"
	}
	return reportText(run["status"])
}

func reportJavaAnalysisText(run map[string]any) string {
	summary := reportMap(run["analysisSummary"])
	if len(summary) == 0 {
		return "历史运行未保存覆盖统计，覆盖范围及诊断数量未知。"
	}
	coverage := reportMap(summary["coverage"])
	count := func(key string) string {
		if coverage[key] == nil {
			return "未知"
		}
		return reportDisplayText(coverage[key])
	}
	lines := []string{fmt.Sprintf("文件：总数 %s，已分析 %s，解析失败 %s", count("totalFiles"), count("analyzedFiles"), count("failedFiles")),
		fmt.Sprintf("方法：总数 %s，已分析 %s；未解析调用 %s", count("totalMethods"), count("analyzedMethods"), count("unresolvedCalls"))}
	engines := reportMap(summary["engines"])
	for _, name := range []string{"source", "bytecode"} {
		engine := reportMap(engines[name])
		lines = append(lines, name+": "+reportDisplayText(engine["status"])+" "+reportText(engine["reason"]))
	}
	lines = append(lines, "诊断数量："+reportDisplayText(summary["diagnosticCount"]))
	for _, item := range reportMapSlice(summary["diagnostics"]) {
		lines = append(lines, reportText(item["code"])+" "+reportText(item["path"])+" "+reportText(item["message"]))
	}
	if summary["diagnosticsTruncated"] == true {
		lines = append(lines, "诊断内容已截断。")
	}
	if summary["findingsTruncated"] == true {
		lines = append(lines, "检测发现已截断。")
	}
	return strings.Join(lines, "\n")
}

func reportNullnessTraceText(finding map[string]any) string {
	evidence := reportMap(finding["evidence"])
	steps := reportMapSlice(evidence["nullnessTrace"])
	if len(steps) == 0 {
		steps = reportMapSlice(evidence["securityTrace"])
	}
	steps = append(steps, reportMapSlice(evidence["bindingLocations"])...)
	if len(steps) > 32 {
		steps = steps[:32]
	}
	lines := make([]string, 0, len(steps))
	if evidence["traceIncomplete"] == true {
		lines = append(lines, "空值传播路径不完整：无法验证的位置已省略。")
	}
	for _, step := range steps {
		lines = append(lines, fmt.Sprintf("%s %s:%s:%s — %s", reportText(step["kind"]), reportText(step["path"]), reportDisplayText(step["line"]), reportDisplayText(step["column"]), reportText(step["message"])))
	}
	return strings.Join(lines, "\n")
}

func reportTraceTitle(finding map[string]any) string {
	if len(reportMapSlice(reportMap(finding["evidence"])["securityTrace"])) > 0 {
		return "安全行为证据"
	}
	return "空值传播路径"
}
