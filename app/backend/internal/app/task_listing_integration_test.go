package app

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func archiveListFixture(t *testing.T) *taskService {
	t.Helper()
	s := cleanupTestService(t)
	cleanupBlob(t, s, "blob")
	cleanupExec(t, s, `INSERT INTO uploads (id, created_by, original_name, declared_size, blob_id, status,
	 content_type, validation_status, expires_at) VALUES ('upload', 1, 'archive.zip', 4, 'blob', 'complete', 'application/zip', 'valid', DATE_ADD(UTC_TIMESTAMP(), INTERVAL 1 DAY))`)
	cleanupTask(t, s, "parent", "blob", "upload", "archive")
	cleanupTask(t, s, "other-mode", "blob", "upload", "binary")
	cleanupTask(t, s, "child-old", "blob", "", "binary")
	cleanupTask(t, s, "child-new", "blob", "", "binary")
	cleanupExec(t, s, `UPDATE tasks SET status = 'failed', display_name = 'old-failure', detected_format = 'elf64' WHERE id = 'child-old'`)
	cleanupExec(t, s, `UPDATE tasks SET status = 'scanning', display_name = 'new-active', detected_format = 'pe32' WHERE id = 'child-new'`)
	cleanupExec(t, s, `INSERT INTO runs (id, kind, status, task_id, subject_type, subject_id, idempotency_key, created_at)
	 VALUES ('old-import', 'archive_import', 'complete', 'parent', 'file_node', 'file-parent', 'old-import', '2026-01-01'),
	 ('new-import', 'archive_import', 'complete', 'parent', 'file_node', 'file-parent', 'new-import', '2026-01-02')`)
	cleanupExec(t, s, `INSERT INTO archive_entries (import_run_id, ordinal, logical_path, size_bytes, status, blob_id, created_task_id)
	 VALUES ('old-import', 1, 'old/path/failing.elf', 4, 'task_created', 'blob', 'child-old'),
	 ('new-import', 1, 'new/path/active.exe', 4, 'task_created', 'blob', 'child-new'),
	 ('new-import', 2, 'unused.elf', 4, 'materialized', 'blob', NULL)`)
	return s
}

func archiveListRequest(t *testing.T, s *taskService, url string) *httptest.ResponseRecorder {
	t.Helper()
	router := gin.New()
	router.GET("/tasks", s.list)
	router.GET("/tasks/:taskID/children", s.listTaskChildren)
	router.GET("/archive-imports", s.listArchiveImports)
	router.GET("/archive-imports/:importID", s.getArchiveImport)
	router.GET("/archive-imports/:importID/entries", s.listArchiveImportEntries)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, url, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("%s: status=%d body=%s", url, w.Code, w.Body.String())
	}
	return w
}

func archiveTaskPage(t *testing.T, s *taskService, url string) ([]taskSummary, string) {
	t.Helper()
	w := archiveListRequest(t, s, url)
	var response struct {
		Tasks      []taskSummary `json:"tasks"`
		NextCursor string        `json:"next_cursor"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	return response.Tasks, response.NextCursor
}

func TestUnifiedTaskListGroupsAllImportHistoryAndFiltersChildren(t *testing.T) {
	s := archiveListFixture(t)
	tasks, _ := archiveTaskPage(t, s, "/tasks")
	if len(tasks) != 2 {
		t.Fatalf("top-level rows=%d, want independent task and archive parent", len(tasks))
	}
	var archive *taskArchiveSummary
	for _, task := range tasks {
		if task.ID == "parent" {
			archive = task.Archive
		}
	}
	if archive == nil || archive.ImportID != "new-import" || archive.ChildCount != 2 || archive.ActiveCount != 1 || archive.FailedCount != 1 || archive.CompletedCount != 0 {
		t.Fatalf("archive summary=%+v", archive)
	}
	for _, query := range []string{"keyword=old/path", "status=FAILED", "input_type=elf64", "tag=elf64", "analysis_mode=archive"} {
		tasks, _ = archiveTaskPage(t, s, "/tasks?"+query)
		if len(tasks) != 1 || tasks[0].ID != "parent" {
			t.Fatalf("filter %s: %+v", query, tasks)
		}
	}
	tasks, _ = archiveTaskPage(t, s, "/tasks?keyword=old-failure&status=SCANNING")
	if len(tasks) != 0 {
		t.Fatal("filters on different children must not produce a match")
	}
	children, cursor := archiveTaskPage(t, s, "/tasks/parent/children?page_size=1")
	if len(children) != 1 || cursor == "" || children[0].ArchivePath == "" {
		t.Fatalf("child page=%+v cursor=%q", children, cursor)
	}
	next, _ := archiveTaskPage(t, s, "/tasks/parent/children?page_size=1&cursor="+cursor)
	if len(next) != 1 || next[0].ID == children[0].ID {
		t.Fatalf("next child page=%+v", next)
	}
	w := archiveListRequest(t, s, "/archive-imports?task_id=parent")
	var history struct {
		Items []archiveImportRecord `json:"items"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &history); err != nil || len(history.Items) != 2 {
		t.Fatalf("history=%s error=%v", w.Body.String(), err)
	}
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest(http.MethodGet, "/overview", nil)
	stats, err := s.collectOverview(ctx, time.Now().UTC(), 7)
	if err != nil || stats.Total != 3 {
		t.Fatalf("overview must count independent task plus children, got %+v error=%v", stats, err)
	}
}

func TestArchiveSourceCleanupPreservesHistoryChildrenAndOtherModes(t *testing.T) {
	s := archiveListFixture(t)
	requestCleanup(t, s, "parent", currentUser{ID: 1, Role: "operator"}, http.StatusConflict)
	router := gin.New()
	user := currentUser{ID: 2, Role: "operator"}
	router.DELETE("/tasks/:taskID/archive-source", func(c *gin.Context) { c.Set("currentUser", user); s.cleanupArchiveSource(c) })
	request := func(expected int) {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/tasks/parent/archive-source", nil))
		if w.Code != expected {
			t.Fatalf("cleanup: status=%d body=%s", w.Code, w.Body.String())
		}
	}
	request(http.StatusForbidden)
	user = currentUser{ID: 1, Role: "operator"}
	cleanupExec(t, s, `UPDATE runs SET status='running' WHERE id='new-import'`)
	request(http.StatusConflict)
	cleanupExec(t, s, `UPDATE runs SET status='complete' WHERE id='new-import'`)
	request(http.StatusNoContent)
	request(http.StatusNoContent)
	cleanupCount(t, s, `SELECT COUNT(*) FROM tasks WHERE id='other-mode' AND deleted_at IS NULL`, 1)
	cleanupCount(t, s, `SELECT COUNT(*) FROM archive_entries WHERE created_task_id IS NOT NULL`, 2)
	cleanupCount(t, s, `SELECT COUNT(*) FROM archive_entries WHERE created_task_id IS NULL`, 0)
	cleanupCount(t, s, `SELECT COUNT(*) FROM uploads WHERE id='upload' AND status='complete'`, 1)
	cleanupCount(t, s, `SELECT COUNT(*) FROM runs WHERE task_id='parent'`, 2)
	tasks, _ := archiveTaskPage(t, s, "/tasks?analysis_mode=archive")
	if len(tasks) != 1 || tasks[0].Archive == nil || tasks[0].Archive.SourceRetained {
		t.Fatalf("retained group=%+v", tasks)
	}
	children, _ := archiveTaskPage(t, s, "/tasks/parent/children")
	if len(children) != 2 {
		t.Fatalf("children=%+v", children)
	}
	// A newer, now-empty import is inaccessible after source removal; the group
	// must point at the older import that still owns a surviving child.
	cleanupExec(t, s, `UPDATE tasks SET deleted_at=UTC_TIMESTAMP(6) WHERE id='child-new'`)
	tasks, _ = archiveTaskPage(t, s, "/tasks?analysis_mode=archive")
	if len(tasks) != 1 || tasks[0].Archive.ImportID != "old-import" || tasks[0].Archive.ChildCount != 1 {
		t.Fatalf("retained historical group=%+v", tasks)
	}
}

func TestUnsupportedArchiveWithoutImportCanBeDeleted(t *testing.T) {
	s := cleanupTestService(t)
	cleanupBlob(t, s, "blob")
	cleanupTask(t, s, "unsupported", "blob", "", "archive")
	requestCleanup(t, s, "unsupported", currentUser{ID: 1, Role: "operator"}, http.StatusNoContent)
	drainCleanup(t, s)
	cleanupCount(t, s, `SELECT COUNT(*) FROM tasks`, 0)
}

func TestSoftDeletedArchiveChildIsNotCountedOrLinkedBeforePurge(t *testing.T) {
	s := archiveListFixture(t)
	cleanupExec(t, s, `UPDATE tasks SET status='deleting', deleted_at=UTC_TIMESTAMP(6) WHERE id='child-old'`)
	w := archiveListRequest(t, s, "/archive-imports/old-import")
	var archive archiveImportRecord
	if err := json.Unmarshal(w.Body.Bytes(), &archive); err != nil {
		t.Fatal(err)
	}
	if archive.CreatedTasks != 0 || archive.EligibleEntries != 0 {
		t.Fatalf("deleted child counted as live/eligible: %+v", archive)
	}
	w = archiveListRequest(t, s, "/archive-imports/old-import/entries")
	var entries struct {
		Items []archiveEntryResponse `json:"items"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &entries); err != nil {
		t.Fatal(err)
	}
	if len(entries.Items) != 1 || entries.Items[0].TaskID != "" || entries.Items[0].Status != "skipped" {
		t.Fatalf("deleted child link remains: %+v", entries.Items)
	}
	children, _ := archiveTaskPage(t, s, "/tasks/parent/children")
	if len(children) != 1 || children[0].ID != "child-new" {
		t.Fatalf("soft-deleted children=%+v", children)
	}
	var entryID string
	if err := s.db.QueryRow(`SELECT CAST(id AS CHAR) FROM archive_entries WHERE created_task_id='child-old'`).Scan(&entryID); err != nil {
		t.Fatal(err)
	}
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest(http.MethodPost, "/archive-imports/old-import/task-batches", nil)
	if _, _, err := s.createTaskFromArchiveEntry(ctx, "old-import", entryID, 1, "stale-selection"); !errors.Is(err, errArchiveEntryNotEligible) {
		t.Fatalf("stale selection returned deleted child: %v", err)
	}
}
