package app

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestExecutionStatusQueryIsIndependentOfLifecycleStatus(t *testing.T) {
	options, err := parseTaskListOptions(url.Values{"status": {"SUCCEEDED"}, "execution_status": {" decompiled "}})
	if err != nil || options.Status != "ready" || options.ExecutionStatus != "DECOMPILED" {
		t.Fatalf("query=%+v error=%v", options, err)
	}
	if _, err := parseTaskListOptions(url.Values{"execution_status": {"SUCCEEDED"}}); err == nil {
		t.Fatal("ambiguous lifecycle status must not be accepted as an execution milestone")
	}
}

func addExecutionRun(t *testing.T, s *taskService, task, id, kind, status, subjectType, subject, quality string, sequence int) {
	t.Helper()
	cleanupExec(t, s, `INSERT INTO runs
	 (id, kind, status, task_id, subject_type, subject_id, idempotency_key, result_quality, created_at)
	 VALUES (?, ?, ?, ?, ?, ?, ?, NULLIF(?, ''), ?)`, id, kind, status, task, subjectType, subject, id, quality,
		fmt.Sprintf("2026-01-01 00:00:%02d", sequence))
}

func assertExecutionStatus(t *testing.T, s *taskService, task, expected string) {
	t.Helper()
	var status string
	if err := s.db.QueryRow(`SELECT `+taskExecutionStatusSQL("t")+` FROM tasks t WHERE t.id = ?`, task).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != expected {
		t.Fatalf("task %s execution status=%s, want %s", task, status, expected)
	}
}

func TestTaskExecutionMilestonesComeFromActualAnalysisRuns(t *testing.T) {
	s := cleanupTestService(t)
	cleanupBlob(t, s, "blob")
	cases := []struct{ kind, status, quality, expected string }{
		{"scan", "queued", "", "PREPARING"},
		{"scan", "running", "", "PREPARING"},
		{"scan", "complete", "", "UPLOADED"},
		{"scan", "failed", "", "FAILED"},
		{"jvm_decompile", "queued", "", "DECOMPILING"},
		{"native_decompile", "running", "", "DECOMPILING"},
		{"pyc_decompile", "complete", "source", "DECOMPILED"},
		{"jvm_decompile", "complete", "partial_source", "DECOMPILE_PARTIAL"},
		{"pyc_decompile", "complete", "bytecode_only", "DECOMPILE_PARTIAL"},
		{"native_decompile", "complete", "", "DECOMPILE_PARTIAL"},
		{"jvm_decompile", "failed", "", "DECOMPILE_FAILED"},
		{"c_check", "queued", "", "SCANNING"},
		{"java_check", "running", "", "SCANNING"},
		{"python_check", "complete", "source", "SCAN_COMPLETED"},
		{"java_check", "complete", "partial_source", "SCAN_PARTIAL"},
		{"c_check", "partial", "source", "SCAN_PARTIAL"},
		{"python_check", "failed", "", "SCAN_FAILED"},
		{"trivy_scan", "complete", "", "SCAN_COMPLETED"},
		{"trivy_scan", "failed", "", "SCAN_FAILED"},
		{"trivy_scan", "cancelled", "", "CANCELLED"},
		{"trivy_scan", "unsupported", "", "UNSUPPORTED"},
	}
	for i, item := range cases {
		task := fmt.Sprintf("task-%d", i)
		cleanupTask(t, s, task, "blob", "", "binary")
		addExecutionRun(t, s, task, fmt.Sprintf("run-%d", i), item.kind, item.status, "file_node", "file-"+task, item.quality, 0)
		assertExecutionStatus(t, s, task, item.expected)
	}
	cleanupTask(t, s, "just-uploaded", "blob", "", "binary")
	assertExecutionStatus(t, s, "just-uploaded", "UPLOADED")
	cleanupExec(t, s, `UPDATE tasks SET status='queued' WHERE id='just-uploaded'`)
	assertExecutionStatus(t, s, "just-uploaded", "PREPARING")
}

func TestTaskExecutionUsesLatestAttemptPerSubjectAndExposesUnfinishedWork(t *testing.T) {
	s := cleanupTestService(t)
	cleanupBlob(t, s, "blob")
	cleanupTask(t, s, "task", "blob", "", "binary")
	addExecutionRun(t, s, "task", "old", "java_check", "failed", "source_project", "project", "", 0)
	addExecutionRun(t, s, "task", "retry", "java_check", "running", "source_project", "project", "", 1)
	assertExecutionStatus(t, s, "task", "SCANNING")
	cleanupExec(t, s, `UPDATE runs SET status='complete', result_quality='source' WHERE id='retry'`)
	assertExecutionStatus(t, s, "task", "SCAN_COMPLETED")
	addExecutionRun(t, s, "task", "other-file", "jvm_decompile", "queued", "file_node", "other", "", 2)
	assertExecutionStatus(t, s, "task", "DECOMPILING")
	cleanupExec(t, s, `UPDATE runs SET status='complete', result_quality='partial_source' WHERE id='other-file'`)
	assertExecutionStatus(t, s, "task", "SCAN_PARTIAL")
	addExecutionRun(t, s, "task", "other-failed-project", "java_check", "failed", "source_project", "other-project", "", 3)
	assertExecutionStatus(t, s, "task", "SCAN_FAILED")
	cleanupExec(t, s, `UPDATE tasks SET status='deleting' WHERE id='task'`)
	assertExecutionStatus(t, s, "task", "DELETING")
}

func TestTaskExecutionBreaksIdenticalRunTimestampsDeterministically(t *testing.T) {
	s := cleanupTestService(t)
	cleanupBlob(t, s, "blob")
	cleanupTask(t, s, "task", "blob", "", "binary")
	addExecutionRun(t, s, "task", "a", "jvm_decompile", "failed", "file_node", "file-task", "", 0)
	addExecutionRun(t, s, "task", "z", "jvm_decompile", "complete", "file_node", "file-task", "source", 0)
	assertExecutionStatus(t, s, "task", "DECOMPILED")
}

func TestRecompileInvalidatesChecksOfSupersededSourceProject(t *testing.T) {
	s := cleanupTestService(t)
	cleanupBlob(t, s, "blob")
	cleanupTask(t, s, "task", "blob", "", "binary")
	addExecutionRun(t, s, "task", "decompile-old", "jvm_decompile", "complete", "file_node", "file-task", "source", 0)
	cleanupExec(t, s, `INSERT INTO source_projects (id, task_id, file_node_id, run_id, source_kind, language, result_quality, root_storage_key)
	 VALUES ('project', 'task', 'file-task', 'decompile-old', 'jvm', 'java', 'source', 'project')`)
	addExecutionRun(t, s, "task", "check-old", "java_check", "complete", "source_project", "project", "source", 1)
	assertExecutionStatus(t, s, "task", "SCAN_COMPLETED")
	addExecutionRun(t, s, "task", "decompile-new", "jvm_decompile", "queued", "file_node", "file-task", "", 2)
	assertExecutionStatus(t, s, "task", "DECOMPILING")
	cleanupExec(t, s, `UPDATE runs SET status='complete', result_quality='source' WHERE id='decompile-new'`)
	assertExecutionStatus(t, s, "task", "DECOMPILED")
}

func TestDetectionCompletionRequiresCoverageOfEveryLatestSourceProject(t *testing.T) {
	s := cleanupTestService(t)
	cleanupBlob(t, s, "blob")
	cleanupTask(t, s, "task", "blob", "", "binary")
	cleanupExec(t, s, `INSERT INTO file_nodes (id, task_id, blob_id, logical_path, node_kind)
	 VALUES ('file-second', 'task', 'blob', '/second.jar', 'file')`)
	addExecutionRun(t, s, "task", "decompile-one", "jvm_decompile", "complete", "file_node", "file-task", "source", 0)
	addExecutionRun(t, s, "task", "decompile-two", "jvm_decompile", "complete", "file_node", "file-second", "source", 1)
	cleanupExec(t, s, `INSERT INTO source_projects (id, task_id, file_node_id, run_id, source_kind, language, result_quality, root_storage_key)
	 VALUES ('project-one', 'task', 'file-task', 'decompile-one', 'jvm', 'java', 'source', 'project-one'),
	 ('project-two', 'task', 'file-second', 'decompile-two', 'jvm', 'java', 'source', 'project-two')`)
	assertExecutionStatus(t, s, "task", "DECOMPILED")
	addExecutionRun(t, s, "task", "check-one", "java_check", "complete", "source_project", "project-one", "source", 2)
	assertExecutionStatus(t, s, "task", "SCAN_PARTIAL")
	addExecutionRun(t, s, "task", "check-two", "java_check", "complete", "source_project", "project-two", "source", 3)
	assertExecutionStatus(t, s, "task", "SCAN_COMPLETED")
	cleanupExec(t, s, `UPDATE runs SET result_quality='partial_source' WHERE id='check-two'`)
	assertExecutionStatus(t, s, "task", "SCAN_PARTIAL")
	// Image scans do not depend on source projects or source-check coverage.
	cleanupExec(t, s, `DELETE FROM runs WHERE id IN ('check-one', 'check-two')`)
	addExecutionRun(t, s, "task", "image-scan", "trivy_scan", "complete", "file_node", "file-task", "", 4)
	assertExecutionStatus(t, s, "task", "SCAN_COMPLETED")
}

func TestExecutionStatusFiltersBeforePagingAndArchiveCountsOnlyDetectionCompletion(t *testing.T) {
	s := archiveListFixture(t)
	cleanupExec(t, s, `UPDATE tasks SET status='ready' WHERE id IN ('child-old', 'child-new')`)
	addExecutionRun(t, s, "child-old", "child-scan", "scan", "queued", "file_node", "file-child-old", "", 0)
	tasks, _ := archiveTaskPage(t, s, "/tasks?analysis_mode=archive")
	if len(tasks) != 1 || tasks[0].Archive.ActiveCount != 1 || tasks[0].Archive.CompletedCount != 0 {
		t.Fatalf("queued input preparation must keep the archive active for polling: %+v", tasks)
	}
	children, _ := archiveTaskPage(t, s, "/tasks/parent/children?execution_status=PREPARING")
	if len(children) != 1 || children[0].ID != "child-old" || children[0].ExecutionStatus != "PREPARING" {
		t.Fatalf("new child must expose its queued preparation: %+v", children)
	}
	cleanupExec(t, s, `UPDATE runs SET status='complete' WHERE id='child-scan'`)
	addExecutionRun(t, s, "child-new", "child-check", "java_check", "complete", "source_project", "project", "source", 1)
	children, cursor := archiveTaskPage(t, s, "/tasks/parent/children?page_size=1&execution_status=SCAN_COMPLETED")
	if len(children) != 1 || children[0].ID != "child-new" || children[0].ExecutionStatus != "SCAN_COMPLETED" || cursor != "" {
		t.Fatalf("filtered children=%+v cursor=%q", children, cursor)
	}
	tasks, _ = archiveTaskPage(t, s, "/tasks?execution_status=SCAN_COMPLETED")
	if len(tasks) != 1 || tasks[0].ID != "parent" || tasks[0].Archive.CompletedCount != 1 || tasks[0].Archive.ActiveCount != 0 {
		t.Fatalf("filtered archive=%+v", tasks)
	}
	cleanupExec(t, s, `UPDATE runs SET result_quality='partial_source' WHERE id='child-check'`)
	tasks, _ = archiveTaskPage(t, s, "/tasks?analysis_mode=archive")
	if len(tasks) != 1 || tasks[0].Archive.CompletedCount != 0 {
		t.Fatalf("partial scan must not count as fully completed: %+v", tasks)
	}
	// Detail uses the same authoritative milestone as list and child endpoints.
	router := gin.New()
	router.GET("/tasks/:taskID", s.get)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/tasks/child-old", nil))
	var detail struct {
		Task taskSummary `json:"task"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &detail); err != nil || w.Code != http.StatusOK || detail.Task.ExecutionStatus != "UPLOADED" {
		t.Fatalf("detail status=%d body=%s error=%v", w.Code, w.Body.String(), err)
	}
}
