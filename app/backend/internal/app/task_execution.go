package app

import (
	"fmt"
	"strings"
)

// Execution status describes the analysis milestone, independently of tasks.status,
// which describes input availability and is also used by cleanup and scheduling.
func taskExecutionStatus(raw string) (string, error) {
	value := strings.ToUpper(strings.TrimSpace(raw))
	switch value {
	case "", "UPLOADED", "PREPARING", "DECOMPILE_QUEUED", "DECOMPILING", "DECOMPILED",
		"DECOMPILE_PARTIAL", "DECOMPILE_FAILED", "SCAN_QUEUED", "SCANNING", "SCAN_COMPLETED",
		"SCAN_PARTIAL", "SCAN_FAILED", "FAILED", "CANCELLED", "UNSUPPORTED", "DELETING", "DELETED":
		return value, nil
	default:
		return "", fmt.Errorf("invalid task execution status")
	}
}

// taskExecutionStatusSQL is shared by display, filtering before pagination, and
// archive counts. Aliases are fixed by our queries, never supplied by a client.
// Only the latest attempt per kind and subject contributes: a successful retry
// replaces its earlier failure, while another file's unfinished work still counts.
// Runs have microsecond creation timestamps; ID breaks exact ties consistently
// with the API's existing run ordering rather than relying on row iteration order.
func taskExecutionStatusSQL(taskAlias string) string {
	return `CASE
	 WHEN ` + taskAlias + `.status = 'deleting' THEN 'DELETING'
	 WHEN ` + taskAlias + `.status = 'deleted' THEN 'DELETED'
	 ELSE COALESCE((SELECT CASE MAX(CASE
	  WHEN execution_run.status IN ('queued', 'running') AND execution_run.kind IN ('trivy_scan', 'c_check', 'java_check', 'python_check') THEN 150
	  WHEN execution_run.status IN ('queued', 'running') AND execution_run.kind IN ('native_decompile', 'jvm_decompile', 'pyc_decompile') THEN 140
	  WHEN execution_run.status IN ('queued', 'running') AND execution_run.kind = 'scan' THEN 130
	  WHEN execution_run.status = 'failed' AND execution_run.kind IN ('trivy_scan', 'c_check', 'java_check', 'python_check') THEN 120
	  WHEN execution_run.status = 'failed' AND execution_run.kind IN ('native_decompile', 'jvm_decompile', 'pyc_decompile') THEN 110
	  WHEN execution_run.status = 'failed' THEN 100
	  WHEN execution_run.status = 'cancelled' THEN 90
	  WHEN execution_run.status = 'unsupported' THEN 80
	  WHEN execution_run.kind IN ('trivy_scan', 'c_check', 'java_check', 'python_check')
	   AND (execution_run.status = 'partial' OR (execution_run.status = 'complete' AND execution_run.result_quality IN ('partial_source', 'bytecode_only'))) THEN 70
	  WHEN execution_run.kind IN ('native_decompile', 'jvm_decompile', 'pyc_decompile')
	   AND (execution_run.status = 'partial' OR (execution_run.status = 'complete' AND COALESCE(execution_run.result_quality, '') <> 'source')) THEN 60
	  WHEN execution_run.status = 'complete' AND execution_run.kind IN ('trivy_scan', 'c_check', 'java_check', 'python_check') THEN 50
	  WHEN execution_run.status = 'complete' AND execution_run.kind IN ('native_decompile', 'jvm_decompile', 'pyc_decompile') THEN 40
	  ELSE 10 END)
	 WHEN 150 THEN 'SCANNING'
	 WHEN 140 THEN 'DECOMPILING'
	 WHEN 130 THEN 'PREPARING'
	 WHEN 120 THEN 'SCAN_FAILED'
	 WHEN 110 THEN 'DECOMPILE_FAILED'
	 WHEN 100 THEN 'FAILED'
	 WHEN 90 THEN 'CANCELLED'
	 WHEN 80 THEN 'UNSUPPORTED'
	 WHEN 70 THEN 'SCAN_PARTIAL'
	 WHEN 60 THEN CASE WHEN MAX(execution_run.kind IN ('trivy_scan', 'c_check', 'java_check', 'python_check')) = 1 THEN 'SCAN_PARTIAL' ELSE 'DECOMPILE_PARTIAL' END
	 WHEN 50 THEN CASE WHEN MAX(execution_run.kind IN ('c_check', 'java_check', 'python_check')) = 1
	  AND MAX(CASE WHEN execution_run.kind IN ('native_decompile', 'jvm_decompile', 'pyc_decompile')
	   AND execution_run.status = 'complete' AND execution_run.result_quality = 'source'
	   AND NOT EXISTS (SELECT 1 FROM source_projects coverage_project
	    JOIN runs coverage_check ON coverage_check.subject_type = 'source_project' AND coverage_check.subject_id = coverage_project.id
	     AND coverage_check.task_id = execution_run.task_id
	     AND coverage_check.kind IN ('c_check', 'java_check', 'python_check') AND coverage_check.status IN ('complete', 'partial')
	    WHERE coverage_project.run_id = execution_run.id AND coverage_project.state = 'ready' AND coverage_project.deleted_at IS NULL)
	   THEN 1 ELSE 0 END) = 1 THEN 'SCAN_PARTIAL' ELSE 'SCAN_COMPLETED' END
	 WHEN 40 THEN 'DECOMPILED'
	 WHEN 10 THEN 'UPLOADED' END
	 FROM runs execution_run
	 WHERE execution_run.task_id = ` + taskAlias + `.id
	 AND execution_run.kind IN ('scan', 'trivy_scan', 'native_decompile', 'jvm_decompile', 'pyc_decompile', 'c_check', 'java_check', 'python_check')
	 AND NOT EXISTS (SELECT 1 FROM runs execution_newer
	  WHERE execution_newer.task_id = execution_run.task_id AND execution_newer.kind = execution_run.kind
	  AND execution_newer.subject_type = execution_run.subject_type AND execution_newer.subject_id = execution_run.subject_id
	  AND (execution_newer.created_at > execution_run.created_at OR (execution_newer.created_at = execution_run.created_at AND execution_newer.id > execution_run.id)))
	 AND NOT EXISTS (SELECT 1 FROM source_projects execution_project
	  JOIN runs execution_source ON execution_source.id = execution_project.run_id
	  JOIN runs execution_replacement ON execution_replacement.task_id = execution_source.task_id
	   AND execution_replacement.kind = execution_source.kind AND execution_replacement.subject_type = execution_source.subject_type
	   AND execution_replacement.subject_id = execution_source.subject_id
	   AND (execution_replacement.created_at > execution_source.created_at OR (execution_replacement.created_at = execution_source.created_at AND execution_replacement.id > execution_source.id))
	  WHERE execution_run.kind IN ('c_check', 'java_check', 'python_check')
	   AND execution_run.subject_type = 'source_project' AND execution_project.id = execution_run.subject_id)),
	 CASE WHEN ` + taskAlias + `.status = 'failed' THEN 'FAILED'
	  WHEN ` + taskAlias + `.status IN ('queued', 'scanning') THEN 'PREPARING'
	  ELSE 'UPLOADED' END) END`
}
