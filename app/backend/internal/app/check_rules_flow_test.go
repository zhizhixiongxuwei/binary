package app

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"binaryscan.local/backend/internal/checkrules"
	"binaryscan.local/backend/internal/config"
	"binaryscan.local/backend/internal/job"
	"binaryscan.local/backend/internal/scanner"
	"binaryscan.local/backend/internal/storage"
	"github.com/gin-gonic/gin"
)

// This uses a disposable database and temporary immutable source artifact. It
// exercises the actual API snapshot, job fence, Scanner HTTP boundary and report
// data without touching any bundled sample or deployed service.
func TestRuleSelectionFlowsFromQueueThroughWorkerAndReport(t *testing.T) {
	s, catalog := ruleCatalogFixture(t)
	ctx := context.Background()
	var sourcePosts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/rules" {
			_ = json.NewEncoder(w).Encode(catalog)
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != "/v1/check" {
			http.Error(w, "unexpected", 404)
			return
		}
		sourcePosts.Add(1)
		var request struct {
			ProjectID      string   `json:"projectId"`
			RuleIDs        []string `json:"ruleIds"`
			CatalogVersion string   `json:"catalogVersion"`
		}
		if json.NewDecoder(r.Body).Decode(&request) != nil {
			t.Error("invalid checker request")
		}
		if len(request.RuleIDs) != 1 || request.RuleIDs[0] != "rule-a" || request.CatalogVersion != catalog.CatalogVersion {
			t.Error("worker did not transmit frozen selection")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"version": "checker-v1", "projectId": request.ProjectID, "status": "complete", "catalogVersion": catalog.CatalogVersion, "appliedRuleIds": request.RuleIDs, "diagnostics": []string{}, "findings": []map[string]any{{"ruleId": "rule-a", "severity": "high", "cwe": "CWE-120", "path": "unit.c", "line": 2, "column": 2, "title": "test finding", "message": "selected rule executed"}}})
	}))
	defer server.Close()
	cfg := config.Config{Worker: config.Worker{WorkRoot: t.TempDir(), BlobRoot: filepath.Join(s.storageRoot, "blobs"), ProjectRoot: filepath.Join(s.storageRoot, "projects"), ArtifactRoot: filepath.Join(s.storageRoot, "artifacts"), CCheckerURL: server.URL}}
	workspace, err := storage.NewWorkspace(cfg.Worker.WorkRoot, "decompile", 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer workspace.Cleanup()
	if err := workspace.WriteFile("unit.c", "c", strings.NewReader("int value(void) {\n return 1;\n}\n")); err != nil {
		t.Fatal(err)
	}
	publication, err := workspace.PublishProject(filepath.Join(cfg.Worker.ProjectRoot, "native"), "project", storage.Manifest{RunID: "decompile", InputBlobID: "blob", InputSHA256: strings.Repeat("a", 64), Kind: "native", Language: "c", Quality: "source"})
	if err != nil {
		t.Fatal(err)
	}
	cleanupExec(t, s, `UPDATE source_projects SET manifest_sha256=? WHERE id='project'`, publication.ManifestSHA256[:])
	for _, file := range publication.Manifest.Files {
		digest, _ := hex.DecodeString(file.SHA256)
		cleanupExec(t, s, `INSERT INTO source_files (id,source_project_id,logical_path,language,sha256,size_bytes,line_count) VALUES (?,'project',?,'c',?,?,?)`, file.ID, file.Path, digest, file.SizeBytes, file.LineCount)
	}
	repository := job.NewRepository(s.db)
	if err := repository.EnsurePool(ctx, "c-check", 1); err != nil {
		t.Fatal(err)
	}
	executor, err := scanner.New(cfg, s.db, repository)
	if err != nil {
		t.Fatal(err)
	}
	launch := func(key string) *job.Claim {
		t.Helper()
		response := ruleRequest(s, key, ruleBody(catalog, "rule-a"))
		if response.Code != 201 {
			t.Fatal(response.Body.String())
		}
		claim, err := repository.Claim(ctx, "test-worker", []job.Kind{job.KindCCheck}, time.Minute)
		if err != nil || claim == nil {
			t.Fatalf("claim=%+v err=%v", claim, err)
		}
		if _, err := repository.Start(ctx, "test-worker", *claim); err != nil {
			t.Fatal(err)
		}
		return claim
	}
	first := launch("flow-one")
	if err := executor.Execute(ctx, *first); err != nil {
		t.Fatal(err)
	}
	if err := repository.Complete(ctx, "test-worker", *first, 1, job.Completion{RunStatus: "complete", JobStatus: "succeeded", AttemptStatus: "succeeded"}); err != nil {
		t.Fatal(err)
	}
	cleanupCount(t, s, `SELECT COUNT(*) FROM findings WHERE rule_id='rule-a'`, 1)
	cleanupCount(t, s, `SELECT COUNT(*) FROM findings WHERE rule_id='rule-b'`, 0)
	var version string
	if err := s.db.QueryRow(`SELECT ruleset_version FROM runs WHERE id=?`, first.RunID).Scan(&version); err != nil || version != catalog.CatalogVersion {
		t.Fatalf("version=%s err=%v", version, err)
	}
	requestContext, _ := gin.CreateTestContext(httptest.NewRecorder())
	requestContext.Request = httptest.NewRequest("GET", "/", nil)
	snapshot, err := s.buildReportSnapshot(requestContext, "task", []string{first.RunID})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(buildHTMLReport(snapshot)), "启用 1/2 条规则") {
		t.Fatal("worker report lost selection scope")
	}
	second := launch("flow-two")
	catalog.CatalogVersion = "sha256:" + strings.Repeat("b", 64)
	if err := executor.Execute(ctx, *second); !errors.Is(err, checkrules.ErrVersion) {
		t.Fatalf("retry/catalog drift not rejected: %v", err)
	}
	if sourcePosts.Load() != 1 {
		t.Fatal("source was submitted after catalog drift")
	}
	cleanupCount(t, s, `SELECT COUNT(*) FROM findings WHERE run_id=?`, 0, second.RunID)
}
