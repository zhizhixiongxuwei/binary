package app

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"binaryscan.local/backend/internal/capability"
	"binaryscan.local/backend/internal/checkrules"
	"binaryscan.local/backend/internal/config"
	"github.com/gin-gonic/gin"
)

func ruleCatalogFixture(t *testing.T) (*taskService, checkrules.Catalog) {
	s := cleanupTestService(t)
	cleanupBlob(t, s, "blob")
	cleanupTask(t, s, "task", "blob", "", "binary")
	cleanupExec(t, s, `INSERT INTO runs (id,kind,status,task_id,subject_type,subject_id,idempotency_key) VALUES ('decompile','native_decompile','complete','task','file_node','file-task','decompile')`)
	cleanupExec(t, s, `INSERT INTO source_projects (id,task_id,file_node_id,run_id,source_kind,language,result_quality,root_storage_key) VALUES ('project','task','file-task','decompile','native','c','source','project')`)
	catalog := checkrules.Catalog{Version: "checker-v1", Language: "c", CatalogVersion: "sha256:" + strings.Repeat("a", 64), Rules: []checkrules.Rule{{ID: "rule-a", Name: "规则A", Description: "说明A", Language: "c", DefaultEnabled: true}, {ID: "rule-b", Name: "规则B", Language: "c", DefaultEnabled: true}}}
	storeRuleCatalog(t, s, "scanner:test", catalog)
	return s, catalog
}
func storeRuleCatalog(t *testing.T, s *taskService, worker string, catalog checkrules.Catalog) {
	t.Helper()
	if err := capability.Store(context.Background(), s.db, worker, "scanner", capability.Report{RuleCatalogs: []checkrules.Observation{{Language: catalog.Language, Status: "available", Catalog: &catalog}}}); err != nil {
		t.Fatal(err)
	}
}
func ruleRequest(s *taskService, key, body string) *httptest.ResponseRecorder {
	router := gin.New()
	router.POST("/tasks/:taskID/projects/:projectID/check", func(c *gin.Context) { c.Set("currentUser", currentUser{ID: 1, Role: "operator"}); s.queueCheck(c) })
	request := httptest.NewRequest(http.MethodPost, "/tasks/task/projects/project/check", strings.NewReader(body))
	request.Header.Set("Idempotency-Key", key)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, request)
	return w
}
func ruleBody(catalog checkrules.Catalog, ids ...string) string {
	body, _ := json.Marshal(map[string]any{"catalogVersion": catalog.CatalogVersion, "ruleIds": ids})
	return string(body)
}
func TestCheckRulesFreezeSelectionAndReplayIdenticalIntent(t *testing.T) {
	s, catalog := ruleCatalogFixture(t)
	for i, body := range []string{`{"catalogVersion":"old"}`, `{"ruleIds":[],"catalogVersion":"old"}`, `{"ruleIds":null,"catalogVersion":"old"}`, ruleBody(catalog, "unknown")} {
		w := ruleRequest(s, string(rune('a'+i)), body)
		if w.Code != 400 {
			t.Fatalf("body=%s code=%d %s", body, w.Code, w.Body.String())
		}
	}
	wrong := catalog
	wrong.CatalogVersion = "sha256:" + strings.Repeat("b", 64)
	if w := ruleRequest(s, "version", ruleBody(wrong, "rule-a")); w.Code != 409 {
		t.Fatalf("version=%d %s", w.Code, w.Body.String())
	}
	first := ruleRequest(s, "custom", ruleBody(catalog, "rule-b", "rule-b"))
	if first.Code != 201 {
		t.Fatalf("first=%d %s", first.Code, first.Body.String())
	}
	var response struct {
		Run queuedRun `json:"run"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Run.Selection == nil || response.Run.Selection.TotalRules != 2 || response.Run.Selection.EnabledCount != 1 || response.Run.Selection.Mode != "custom" {
		t.Fatalf("snapshot=%+v", response.Run.Selection)
	}
	replay := ruleRequest(s, "custom", ruleBody(catalog, "rule-b"))
	if replay.Code != 200 {
		t.Fatalf("replay=%d %s", replay.Code, replay.Body.String())
	}
	if w := ruleRequest(s, "custom", ruleBody(catalog, "rule-a")); w.Code != 409 {
		t.Fatalf("changed intent=%d", w.Code)
	}
	if w := ruleRequest(s, "all", ""); w.Code != 201 {
		t.Fatalf("legacy empty body=%d %s", w.Code, w.Body.String())
	}
	if w := ruleRequest(s, "all-object", `{}`); w.Code != 201 {
		t.Fatalf("legacy empty object=%d %s", w.Code, w.Body.String())
	}
	cleanupExec(t, s, `UPDATE worker_capabilities SET checked_at=DATE_SUB(UTC_TIMESTAMP(6),INTERVAL 10 MINUTE)`)
	if w := ruleRequest(s, "custom", ruleBody(catalog, "rule-b")); w.Code != 200 {
		t.Fatal("replay must not depend on later catalog availability")
	}
	if w := ruleRequest(s, "new-stale", ruleBody(catalog, "rule-a")); w.Code != 409 || !strings.Contains(w.Body.String(), "rule_catalog_stale") {
		t.Fatalf("stale=%d %s", w.Code, w.Body.String())
	}
}

func TestRuleSelectionParserAcceptsOnlyLegacyEmptyBodiesOrExplicitSelection(t *testing.T) {
	for _, body := range []string{"", " ", `{}`, " { } "} {
		ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
		ctx.Request = httptest.NewRequest("POST", "/", strings.NewReader(body))
		input, err := readCheckSelection(ctx)
		if err != nil || !input.All {
			t.Fatalf("legacy body %q input=%+v err=%v", body, input, err)
		}
	}
	for _, body := range []string{`null`, `[]`, `{"unknown":1}`, `{"ruleIds":[]}`, `{"catalogVersion":null}`, `{"ruleIds":null}`, `{"ruleIds":[],"catalogVersion":"old"}`} {
		ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
		ctx.Request = httptest.NewRequest("POST", "/", strings.NewReader(body))
		if _, err := readCheckSelection(ctx); err == nil {
			t.Fatalf("invalid body accepted: %s", body)
		}
	}
}
func TestRuleCatalogReadUsesFreshLanguageReportsAndRejectsConflicts(t *testing.T) {
	s, catalog := ruleCatalogFixture(t)
	router := gin.New()
	router.GET("/tasks/:taskID/projects/:projectID/check-rules", s.projectCheckRules)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/tasks/task/projects/project/check-rules", nil))
	var result projectRuleCatalog
	_ = json.Unmarshal(w.Body.Bytes(), &result)
	if w.Code != 200 || !result.Available || result.Language != "c" || len(result.Rules) != 2 {
		t.Fatalf("catalog=%s", w.Body.String())
	}
	if err := capability.Store(context.Background(), s.db, "scanner:old", "scanner", capability.Report{}); err != nil {
		t.Fatal(err)
	}
	if w := ruleRequest(s, "mixed-deployment", ruleBody(catalog, "rule-a")); w.Code != 409 || !strings.Contains(w.Body.String(), "rule_catalog_conflict") {
		t.Fatalf("mixed deployment=%d %s", w.Code, w.Body.String())
	}
	cleanupExec(t, s, `DELETE FROM worker_capabilities WHERE worker_id='scanner:old'`)
	catalog.CatalogVersion = "sha256:" + strings.Repeat("b", 64)
	storeRuleCatalog(t, s, "scanner:other", catalog)
	if w := ruleRequest(s, "conflict", ruleBody(catalog, "rule-a")); w.Code != 409 || !strings.Contains(w.Body.String(), "rule_catalog_conflict") {
		t.Fatalf("conflict=%d %s", w.Code, w.Body.String())
	}
	cleanupExec(t, s, `DELETE FROM worker_capabilities`)
	if w := ruleRequest(s, "missing", ""); w.Code != 503 {
		t.Fatalf("missing=%d", w.Code)
	}
}
func TestRuleSelectionAppearsInHistoryAndImmutableReports(t *testing.T) {
	s, catalog := ruleCatalogFixture(t)
	w := ruleRequest(s, "custom", ruleBody(catalog, "rule-a"))
	if w.Code != 201 {
		t.Fatal(w.Body.String())
	}
	var response struct {
		Run queuedRun `json:"run"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &response)
	cleanupExec(t, s, `UPDATE runs SET status='complete',completed_at=UTC_TIMESTAMP(6) WHERE id=?`, response.Run.ID)
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest("GET", "/", nil)
	runs, err := s.queryRuns(ctx, "task")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, run := range runs {
		if run["id"] == response.Run.ID {
			selection := run["selection"].(*checkrules.Selection)
			found = selection.EnabledCount == 1 && selection.TotalRules == 2
		}
	}
	if !found {
		t.Fatal("history lost rule selection")
	}
	snapshot, err := s.buildReportSnapshot(ctx, "task", []string{response.Run.ID})
	if err != nil {
		t.Fatal(err)
	}
	jsonBody, _ := json.Marshal(snapshot)
	if !bytes.Contains(jsonBody, []byte(`"enabled_rule_ids":["rule-a"]`)) {
		t.Fatal("JSON snapshot lost selected IDs")
	}
	if html := string(buildHTMLReport(snapshot)); !strings.Contains(html, "启用 1/2 条规则") || !strings.Contains(html, "rule-a") || strings.Contains(html, "rule-b") {
		t.Fatalf("HTML scope incorrect: %s", html)
	}
	docx, err := buildDOCXReport(snapshot)
	if err != nil || len(docx) == 0 {
		t.Fatalf("DOCX generation err=%v", err)
	}
	archive, err := zip.NewReader(bytes.NewReader(docx), int64(len(docx)))
	if err != nil {
		t.Fatal(err)
	}
	checked := false
	for _, file := range archive.File {
		if file.Name == "word/document.xml" {
			reader, err := file.Open()
			if err != nil {
				t.Fatal(err)
			}
			document, _ := io.ReadAll(reader)
			reader.Close()
			checked = bytes.Contains(document, []byte("启用 1/2 条规则")) && bytes.Contains(document, []byte("rule-a")) && !bytes.Contains(document, []byte("rule-b"))
		}
	}
	if !checked {
		t.Fatal("DOCX lost immutable selection coverage")
	}
	if text := reportRuleSelectionText(map[string]any{"kind": "c_check", "selection": nil}); !strings.Contains(text, "未记录") {
		t.Fatal("legacy incorrectly claimed full coverage")
	}
	if time.Since(response.Run.CreatedAt) > time.Minute {
		t.Fatal("unexpected queued run time")
	}
}

func TestAuthenticatedReaderCanReadRulesButCannotQueueChecks(t *testing.T) {
	s, catalog := ruleCatalogFixture(t)
	cleanupExec(t, s, `INSERT INTO users (id,public_id,username,password_hash,role) VALUES (4,'reader','reader','unused','reader')`)
	server, err := NewServer(config.Config{Version: "test", App: config.App{StorageRoot: s.storageRoot}}, s.db)
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []struct {
		name       string
		id         int
		postStatus int
	}{{"reader", 4, 403}, {"operator", 1, 201}, {"administrator", 3, 201}} {
		token := "rules-test-" + role.name
		digest := sha256.Sum256([]byte(token))
		cleanupExec(t, s, `INSERT INTO sessions (id,user_id,token_hash,csrf_token,expires_at) VALUES (?,?,?,'rules-csrf',DATE_ADD(UTC_TIMESTAMP(6),INTERVAL 1 HOUR))`, role.name, role.id, digest[:])
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			path := "/api/v1/tasks/task/projects/project/check-rules"
			body := ""
			expected := 200
			if method == http.MethodPost {
				path = "/api/v1/tasks/task/projects/project/check"
				body = ruleBody(catalog, "rule-a")
				expected = role.postStatus
			}
			request := httptest.NewRequest(method, path, strings.NewReader(body))
			request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
			request.Header.Set("X-CSRF-Token", "rules-csrf")
			request.Header.Set("Idempotency-Key", role.name)
			w := httptest.NewRecorder()
			server.http.Handler.ServeHTTP(w, request)
			if w.Code != expected {
				t.Fatalf("%s %s status=%d body=%s", role.name, method, w.Code, w.Body.String())
			}
		}
	}
}
