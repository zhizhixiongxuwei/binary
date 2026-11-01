package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"binaryscan.local/backend/internal/config"
	"binaryscan.local/backend/internal/database"
	"binaryscan.local/backend/internal/job"
	"binaryscan.local/backend/migrations"

	"github.com/gin-gonic/gin"
	"github.com/go-sql-driver/mysql"
)

// The DSN must point to a disposable MySQL server. Every test creates and drops
// its own database; no application database or existing task is touched.
func cleanupTestService(t *testing.T) *taskService {
	t.Helper()
	dsn := os.Getenv("BINARYSCAN_TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("set BINARYSCAN_TEST_MYSQL_DSN for real MySQL cleanup tests")
	}
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.DBName, cfg.ParseTime, cfg.MultiStatements = "", true, true
	admin, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("task_cleanup_test_%d", time.Now().UnixNano())
	if _, err := admin.Exec("CREATE DATABASE " + name); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec("DROP DATABASE " + name); _ = admin.Close() })
	cfg.DBName = name
	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := database.Migrate(context.Background(), db, migrations.FS); err != nil {
		t.Fatal(err)
	}
	s, err := newTaskService(config.Config{App: config.App{StorageRoot: t.TempDir(), UploadMaxBytes: 1 << 20}}, db)
	if err != nil {
		t.Fatal(err)
	}
	cleanupExec(t, s, `INSERT INTO users (id, public_id, username, password_hash, role)
		VALUES (1, 'owner', 'owner', 'unused', 'operator'), (2, 'other', 'other', 'unused', 'operator'),
		(3, 'admin', 'admin', 'unused', 'administrator')`)
	return s
}

func cleanupExec(t *testing.T, s *taskService, query string, args ...any) {
	t.Helper()
	if _, err := s.db.Exec(query, args...); err != nil {
		t.Fatal(err)
	}
}

func cleanupCount(t *testing.T, s *taskService, query string, expected int, args ...any) {
	t.Helper()
	var count int
	if err := s.db.QueryRow(query, args...).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != expected {
		t.Fatalf("%s: got %d, want %d", query, count, expected)
	}
}

func cleanupBlob(t *testing.T, s *taskService, id string) string {
	t.Helper()
	blob, err := s.blobs.Ingest(strings.NewReader(id), 1024)
	if err != nil {
		t.Fatal(err)
	}
	cleanupExec(t, s, `INSERT INTO blobs (id, sha256, size_bytes, storage_key) VALUES (?, ?, ?, ?)`, id, blob.SHA256[:], blob.SizeBytes, blob.StorageKey)
	return filepath.Join(s.storageRoot, "blobs", filepath.FromSlash(blob.StorageKey))
}

func cleanupTask(t *testing.T, s *taskService, id, blobID, uploadID, mode string) {
	t.Helper()
	var upload any
	if uploadID != "" {
		upload = uploadID
	}
	cleanupExec(t, s, `INSERT INTO tasks (id, created_by, blob_id, upload_id, display_name, analysis_mode, status)
		VALUES (?, 1, ?, ?, ?, ?, 'ready')`, id, blobID, upload, id, mode)
	cleanupExec(t, s, `INSERT INTO file_nodes (id, task_id, blob_id, logical_path, node_kind)
		VALUES (?, ?, ?, '/input.jar', 'file')`, "file-"+id, id, blobID)
}

func requestCleanup(t *testing.T, s *taskService, taskID string, user currentUser, expected int) {
	t.Helper()
	router := gin.New()
	router.DELETE("/tasks/:taskID", func(c *gin.Context) { c.Set("currentUser", user); s.delete(c) })
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/tasks/"+taskID, nil))
	if w.Code != expected {
		t.Fatalf("delete status %d, want %d: %s", w.Code, expected, w.Body.String())
	}
}

func drainCleanup(t *testing.T, s *taskService) {
	t.Helper()
	for range 4 {
		if err := s.cleanupDeletedTasks(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	cleanupCount(t, s, `SELECT COUNT(*) FROM task_cleanup_queue`, 0)
}

func TestTaskDeletionCleansDataAndPreservesSharedSamples(t *testing.T) {
	s := cleanupTestService(t)
	shared := cleanupBlob(t, s, "shared-blob")
	extracted := cleanupBlob(t, s, "extracted-blob")
	cleanupExec(t, s, `INSERT INTO uploads (id, created_by, original_name, declared_size, blob_id, status,
		content_type, validation_status, expires_at) VALUES ('upload', 1, 'sample.jar', 11, 'shared-blob', 'complete',
		'application/octet-stream', 'valid', DATE_ADD(UTC_TIMESTAMP(), INTERVAL 1 DAY))`)
	cleanupTask(t, s, "first", "shared-blob", "upload", "binary")
	cleanupTask(t, s, "second", "shared-blob", "upload", "container")
	cleanupExec(t, s, `INSERT INTO file_nodes (id, task_id, parent_id, blob_id, logical_path, node_kind)
		VALUES ('extracted', 'first', 'file-first', 'extracted-blob', '/Only.class', 'file')`)
	cleanupExec(t, s, `INSERT INTO runs (id, kind, status, task_id, subject_type, subject_id, idempotency_key)
		VALUES ('decompile', 'jvm_decompile', 'running', 'first', 'file_node', 'extracted', 'decompile'),
		('import', 'archive_import', 'complete', 'first', 'file_node', 'file-first', 'import')`)
	cleanupExec(t, s, `INSERT INTO jobs (id, run_id, kind, status, fencing_token, lease_owner, lease_until)
		VALUES (1, 'decompile', 'jvm_decompile', 'running', 7, 'worker', DATE_ADD(UTC_TIMESTAMP(), INTERVAL 1 HOUR))`)
	cleanupExec(t, s, `INSERT INTO job_attempts (job_id, attempt_number, worker_id, fencing_token)
		VALUES (1, 1, 'worker', 7)`)
	cleanupExec(t, s, `INSERT INTO resource_slots (pool, slot_number, job_id, fencing_token, lease_owner)
		VALUES ('jvm', 1, 1, 7, 'worker')`)
	cleanupExec(t, s, `INSERT INTO source_projects (id, task_id, file_node_id, input_blob_id, run_id, source_kind,
		language, result_quality, root_storage_key) VALUES ('project', 'first', 'extracted', 'extracted-blob',
		'decompile', 'jvm', 'java', 'source', 'project')`)
	cleanupExec(t, s, `INSERT INTO source_files (id, source_project_id, logical_path, language, sha256, size_bytes, line_count)
		VALUES ('source', 'project', 'Only.java', 'java', UNHEX(SHA2('source', 256)), 6, 1)`)
	cleanupExec(t, s, `INSERT INTO source_symbols (id, source_project_id, source_file_id, symbol_kind, name, start_line, end_line)
		VALUES ('symbol', 'project', 'source', 'class', 'Only', 1, 1)`)
	cleanupExec(t, s, `INSERT INTO findings (task_id, run_id, source_project_id, source_file_id, finding_type, severity, title, message)
		VALUES ('first', 'decompile', 'project', 'source', 'code', 'high', 'finding', 'evidence')`)
	cleanupExec(t, s, `INSERT INTO llm_explanations (id, task_id, source_project_id, source_file_id, source_sha256,
		cache_key, scope, start_line, end_line, provider, model, content, status)
		VALUES ('llm', 'first', 'project', 'source', UNHEX(SHA2('source', 256)), UNHEX(SHA2('key', 256)),
		'file', 1, 1, 'test', 'test', 'explanation', 'completed')`)
	cleanupExec(t, s, `INSERT INTO task_events (task_id, event_type) VALUES ('first', 'scan.complete')`)
	cleanupExec(t, s, `INSERT INTO run_artifacts (id, task_id, run_id, artifact_kind, media_type, storage_key, size_bytes)
		VALUES ('artifact', 'first', 'decompile', 'evidence', 'application/json', 'first/decompile/7/checker.json', 2)`)
	cleanupExec(t, s, `INSERT INTO reports (id, task_id, created_by, idempotency_key, format, storage_key, selected_run_ids, snapshot)
		VALUES ('report', 'first', 1, 'report', 'json', 'reports/first/report.json', JSON_ARRAY(), JSON_OBJECT())`)
	cleanupExec(t, s, `INSERT INTO archive_entries (import_run_id, ordinal, logical_path, size_bytes, status, blob_id, created_task_id)
		VALUES ('import', 1, '/child.jar', 11, 'task_created', 'shared-blob', 'second')`)
	cleanupExec(t, s, `INSERT INTO archive_report_bundles (id, import_run_id, created_by, idempotency_key,
		storage_key, sha256, size_bytes, options, manifest) VALUES ('bundle', 'import', 1, 'bundle',
		'reports/archive-bundles/import/bundle.zip', UNHEX(SHA2('bundle', 256)), 6, JSON_OBJECT(), JSON_OBJECT())`)
	paths := []string{"projects/jvm/project/Only.java", "artifacts/first/decompile/7/checker.json", "reports/first/report.json", "reports/archive-bundles/import/bundle.zip", "uploads/upload/parts/1"}
	for _, relative := range paths {
		filename := filepath.Join(s.storageRoot, relative)
		if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, []byte("test data"), 0o440); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(filepath.Join(s.storageRoot, "projects/jvm/project"), 0o550); err != nil {
		t.Fatal(err)
	}

	requestCleanup(t, s, "first", currentUser{ID: 2, Role: "operator"}, http.StatusForbidden)
	requestCleanup(t, s, "first", currentUser{ID: 1, Role: "reader"}, http.StatusForbidden)
	cleanupCount(t, s, `SELECT COUNT(*) FROM task_cleanup_queue`, 0)
	requestCleanup(t, s, "first", currentUser{ID: 1, Role: "operator"}, http.StatusNoContent)
	cleanupCount(t, s, `SELECT COUNT(*) FROM tasks WHERE id = 'first' AND status = 'deleting' AND deleted_at IS NOT NULL`, 1)
	requestCleanup(t, s, "first", currentUser{ID: 1, Role: "operator"}, http.StatusNotFound)
	// Reconstruct the service to exercise recovery from persisted work.
	s, err := newTaskService(config.Config{App: config.App{StorageRoot: s.storageRoot, UploadMaxBytes: 1 << 20}}, s.db)
	if err != nil {
		t.Fatal(err)
	}
	drainCleanup(t, s)
	called := false
	err = job.NewRepository(s.db).WithFence(context.Background(), job.Claim{ID: 1, RunID: "decompile", FencingToken: 7}, func(*sql.Tx) error {
		called = true
		return nil
	})
	if !errors.Is(err, job.ErrFenceLost) || called {
		t.Fatalf("deleted worker published results: called=%v, err=%v", called, err)
	}
	for _, table := range []string{"runs", "jobs", "job_attempts", "source_projects", "source_files", "source_symbols", "findings", "llm_explanations", "task_events", "run_artifacts", "reports", "archive_entries", "archive_report_bundles"} {
		cleanupCount(t, s, "SELECT COUNT(*) FROM "+table, 0)
	}
	cleanupCount(t, s, `SELECT COUNT(*) FROM tasks WHERE id = 'second' AND deleted_at IS NULL`, 1)
	cleanupCount(t, s, `SELECT COUNT(*) FROM resource_slots WHERE job_id IS NULL AND fencing_token IS NULL AND lease_owner IS NULL`, 1)
	cleanupCount(t, s, `SELECT COUNT(*) FROM audit_logs WHERE object_id = 'first'`, 2)
	if _, err := os.Stat(shared); err != nil {
		t.Fatal("shared sample was deleted", err)
	}
	if _, err := os.Stat(extracted); !os.IsNotExist(err) {
		t.Fatal("exclusive extracted blob remains", err)
	}
	for _, relative := range paths[:4] {
		if _, err := os.Stat(filepath.Join(s.storageRoot, relative)); !os.IsNotExist(err) {
			t.Fatalf("output remains: %s: %v", relative, err)
		}
	}
	if _, err := os.Stat(filepath.Join(s.storageRoot, paths[4])); err != nil {
		t.Fatal("shared upload data was deleted", err)
	}
	requestCleanup(t, s, "second", currentUser{ID: 3, Role: "administrator"}, http.StatusNoContent)
	drainCleanup(t, s)
	cleanupCount(t, s, `SELECT COUNT(*) FROM uploads`, 0)
	cleanupCount(t, s, `SELECT COUNT(*) FROM blobs`, 0)
	if _, err := os.Stat(shared); !os.IsNotExist(err) {
		t.Fatal("last sample reference was not cleaned", err)
	}
	if _, err := os.Stat(filepath.Join(s.storageRoot, "uploads/upload")); !os.IsNotExist(err) {
		t.Fatal("upload directory remains", err)
	}
}

func TestTaskDeletionDetachesChildAndRetriesFilesystemCleanup(t *testing.T) {
	s := cleanupTestService(t)
	blob := cleanupBlob(t, s, "blob")
	cleanupTask(t, s, "parent", "blob", "", "archive")
	cleanupTask(t, s, "child", "blob", "", "binary")
	cleanupExec(t, s, `INSERT INTO runs (id, kind, status, task_id, subject_type, subject_id, idempotency_key)
		VALUES ('import', 'archive_import', 'complete', 'parent', 'file_node', 'file-parent', 'import')`)
	cleanupExec(t, s, `INSERT INTO archive_entries (import_run_id, ordinal, logical_path, size_bytes, status, blob_id, created_task_id)
		VALUES ('import', 1, '/child.jar', 4, 'task_created', 'blob', 'child')`)
	cleanupExec(t, s, `INSERT INTO archive_report_bundles (id, import_run_id, created_by, idempotency_key,
		storage_key, sha256, size_bytes, options, manifest) VALUES ('bundle', 'import', 1, 'bundle',
		'reports/archive-bundles/import/shared.zip', UNHEX(SHA2('bundle', 256)), 6, JSON_OBJECT(),
		JSON_OBJECT('children', JSON_ARRAY(JSON_OBJECT('task_id', 'child', 'included', TRUE))))`)
	copyPath := filepath.Join(s.storageRoot, "reports/archive-bundles/import/shared.zip")
	if err := os.MkdirAll(filepath.Dir(copyPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(copyPath, []byte("copied child data"), 0o440); err != nil {
		t.Fatal(err)
	}
	requestCleanup(t, s, "child", currentUser{ID: 1, Role: "operator"}, http.StatusNoContent)
	drainCleanup(t, s)
	cleanupCount(t, s, `SELECT COUNT(*) FROM archive_entries WHERE created_task_id IS NULL AND status = 'materialized'`, 1)
	cleanupCount(t, s, `SELECT COUNT(*) FROM archive_report_bundles`, 0)
	if _, err := os.Stat(copyPath); !os.IsNotExist(err) {
		t.Fatal("bundle still contains deleted child's data", err)
	}
	if _, err := os.Stat(blob); err != nil {
		t.Fatal(err)
	}
	cleanupExec(t, s, `INSERT INTO task_cleanup_queue (kind, target) VALUES ('path', 'reports/retry')`)
	var id uint64
	if err := s.db.QueryRow(`SELECT id FROM task_cleanup_queue WHERE target = 'reports/retry'`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	root := s.storageRoot
	s.storageRoot = filepath.Join(root, "not-mounted")
	if err := s.cleanupEntry(context.Background(), id, "path", "reports/retry"); err == nil {
		t.Fatal("missing storage root should retry")
	}
	cleanupCount(t, s, `SELECT COUNT(*) FROM task_cleanup_queue`, 1)
	s.storageRoot = root
	drainCleanup(t, s)
}
