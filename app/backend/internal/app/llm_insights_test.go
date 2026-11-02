package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"

	"binaryscan.local/backend/internal/llm"
)

type memoryProjectInsightCache struct{ record *projectInsightRecord }

func (m *memoryProjectInsightCache) Get(context.Context, explanationTarget, llm.Snapshot) (projectInsightRecord, error) {
	if m.record == nil {
		return projectInsightRecord{}, sql.ErrNoRows
	}
	return *m.record, nil
}
func (m *memoryProjectInsightCache) Put(_ context.Context, _ explanationTarget, _ llm.Snapshot, value projectInsightRecord) error {
	m.record = &value
	return nil
}

func TestArchitecturePersistsAndRegeneratesOnlyOnRequest(t *testing.T) {
	service, _, _ := newTestLLMService(t)
	cache := &memoryProjectInsightCache{}
	service.insightCache = cache
	loads, calls := 0, 0
	service.loadProject = func(context.Context, explanationTarget, int) (insightContext, error) {
		loads++
		return insightFixtureContext(), nil
	}
	service.stream = func(_ context.Context, _ llm.Snapshot, prompt string, delta func(string) error) error {
		calls++
		if !strings.Contains(prompt, "actual.c") {
			t.Fatal("architecture prompt missing verified source")
		}
		return delta(`{"summary":"推断的数据处理结构","nodes":[{"id":"n1","label":"数据模块","role":"data","fileIds":["file"]}],"edges":[],"flow":[]}`)
	}
	router := llmTestRouter(service, "operator")
	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tasks/task/projects/project/insights", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", "csrf-test-token")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, req)
		return response
	}
	if response := post(`{"kind":"architecture"}`); response.Code != 200 {
		t.Fatalf("first generation: %d %s", response.Code, response.Body)
	}
	if response := post(`{"kind":"architecture"}`); response.Code != 200 {
		t.Fatalf("cached generation: %d %s", response.Code, response.Body)
	}
	get := httptest.NewRecorder()
	router.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/api/v1/tasks/task/projects/project/insights?kind=architecture", nil))
	if get.Code != 200 || !strings.Contains(get.Body.String(), "数据模块") {
		t.Fatalf("saved architecture: %d %s", get.Code, get.Body)
	}
	if calls != 1 || loads != 1 {
		t.Fatalf("cache missed: model=%d source=%d", calls, loads)
	}
	if response := post(`{"kind":"architecture","regenerate":true}`); response.Code != 200 || calls != 2 {
		t.Fatalf("regenerate failed: %d %s model=%d", response.Code, response.Body, calls)
	}
}

func TestSemanticSearchRejectsForgedEvidenceAndNavigation(t *testing.T) {
	terms, err := parseSearchTerms(`{"terms":["SELECT","select","x' OR 1=1","rawQuery"]}`)
	if err != nil || len(terms) != 2 || terms[0] != "select" {
		t.Fatalf("unsafe terms: %+v %v", terms, err)
	}
	candidate := searchCandidate{FileID: "real", Path: "db.c", Name: "query", StartLine: 4, EndLine: 12, Code: "int query() { return sqlite3_exec(db, \"SELECT * FROM users\", 0, 0, 0); }"}
	raw := `{"summary":"数据库查询","matches":[{"fileId":"real","startLine":4,"reason":"查询操作","evidence":"sqlite3_exec","path":"forged.c","name":"forged"},{"fileId":"real","startLine":5,"reason":"误导","evidence":"SELECT"},{"fileId":"real","startLine":4,"reason":"虚假证据","evidence":"DROP TABLE"}]}`
	result, err := parseSearchMatches(raw, []searchCandidate{candidate})
	if err != nil || len(result.Matches) != 1 || result.Matches[0].Path != "db.c" || result.Matches[0].Name != "query" || result.Matches[0].EndLine != 12 {
		t.Fatalf("unsafe model result: %+v %v", result, err)
	}
	snippet := searchSnippet(strings.Repeat("padding ", 400)+"sqlite3_exec(db)", []string{"sqlite3"}, 200)
	if !strings.Contains(snippet, "sqlite3_exec") {
		t.Fatal("candidate excerpt missed matching code")
	}
}

func TestInsightSamplesPreserveRangesAndBudget(t *testing.T) {
	source := testExplanationSource(strings.Repeat("中文代码();\r\n", 100))
	excerpts := sampleInsightSource(source, 240)
	chars := 0
	lines := strings.Split(strings.ReplaceAll(source.Content, "\r\n", "\n"), "\n")
	if len(excerpts) < 2 {
		t.Fatal("large files must sample multiple regions")
	}
	for _, excerpt := range excerpts {
		chars += utf8.RuneCountInString(excerpt.Code)
		if excerpt.Code != strings.Join(lines[excerpt.StartLine-1:excerpt.EndLine], "\n") {
			t.Fatal("sample ranges do not match actual source")
		}
	}
	if chars > 240 {
		t.Fatalf("sample exceeded budget: %d", chars)
	}
	small := testExplanationSource("int main() {\r\n return 0;\r\n}")
	full := sampleInsightSource(small, 100)
	if len(full) != 1 || full[0].StartLine != 1 || full[0].EndLine != 3 {
		t.Fatalf("small file was not included in full: %+v", full)
	}
}

func insightFixtureContext() insightContext {
	return insightContext{Excerpts: []insightExcerpt{{FileID: "file", Path: "actual.c", StartLine: 10, EndLine: 20, Code: "int query() {}"}}, TotalFiles: 2, SampledFiles: 1, Truncated: true}
}

func TestInsightRejectsInventedNavigationAndGraphEdges(t *testing.T) {
	source := insightFixtureContext()
	raw := `{"summary":"数据库操作","matches":[
 {"fileId":"file","path":"forged.c","name":"query","startLine":10,"endLine":12,"reason":"SQL调用"},
 {"fileId":"foreign","name":"leak","startLine":10,"endLine":12,"reason":"不属于本项目"},
 {"fileId":"file","name":"outOfRange","startLine":1,"endLine":500,"reason":"不存在"},
 {"fileId":"file","name":"duplicate","startLine":10,"endLine":12,"reason":"重复"}
 ]}`
	result, err := parseInsightResult(raw, "search", source)
	if err != nil || len(result.Matches) != 1 || result.Matches[0].Path != "actual.c" {
		t.Fatalf("unsafe source navigation: %+v %v", result, err)
	}
	architecture := `{"summary":"推断架构","nodes":[{"id":"n1","label":"处理","role":"unknown","fileIds":["file","foreign","file"]}],"edges":[]}`
	result, err = parseInsightResult(architecture, "architecture", source)
	if err != nil || result.Nodes[0].Role != "core" || len(result.Nodes[0].FileIDs) != 1 {
		t.Fatalf("invalid module references: %+v %v", result, err)
	}
	for _, bad := range []string{
		strings.Replace(architecture, `"edges":[]`, `"edges":[{"from":"n1","to":"missing","label":"bad"}]`, 1),
		`{"summary":"invalid","nodes":[]}`,
		"partial JSON {",
	} {
		if _, err := parseInsightResult(bad, "architecture", source); err == nil {
			t.Fatalf("accepted invalid graph: %s", bad)
		}
	}
}

func TestProjectInsightUsesConfiguredModelAndOnlyServerSource(t *testing.T) {
	service, _, _ := newTestLLMService(t)
	loaded := false
	service.searchProject = func(ctx context.Context, target explanationTarget, terms []string) (searchContext, error) {
		if target.TaskID != "task" || target.ProjectID != "project" || !containsString(terms, "query") {
			t.Fatalf("wrong source identity or model terms: %+v %+v", target, terms)
		}
		loaded = true
		return searchContext{TotalFiles: 2, Candidates: []searchCandidate{{FileID: "file", Path: "actual.c", Name: "query", StartLine: 10, EndLine: 12, Code: "int query() {}"}}}, nil
	}
	service.stream = func(ctx context.Context, settings llm.Snapshot, prompt string, delta func(string) error) error {
		if !strings.Contains(prompt, "数据库查询") || settings.APIKey != "test-fixture-key" {
			t.Fatal("request did not reuse saved settings and source")
		}
		if strings.Contains(prompt, "terms") {
			return delta(`{"terms":["query","sqlite"]}`)
		}
		if !strings.Contains(prompt, "actual.c") {
			t.Fatal("candidate was not sent to the model")
		}
		return delta(`{"summary":"查询匹配","matches":[{"fileId":"file","startLine":10,"reason":"SQL调用","evidence":"query()"}]}`)
	}
	request := func(role, body, csrf string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tasks/task/projects/project/insights", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", csrf)
		response := httptest.NewRecorder()
		llmTestRouter(service, role).ServeHTTP(response, req)
		return response
	}
	response := request("operator", `{"kind":"search","query":"数据库查询"}`, "csrf-test-token")
	if response.Code != 200 || !loaded {
		t.Fatalf("project insight failed: %d %s", response.Code, response.Body)
	}
	var payload struct {
		Result   insightResult  `json:"result"`
		Coverage insightContext `json:"coverage"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil || len(payload.Result.Matches) != 1 || payload.Coverage.IndexedFiles != 2 || payload.Coverage.SampledFiles != 1 {
		t.Fatalf("invalid insight response: %s", response.Body)
	}
	if strings.Contains(response.Body.String(), "test-fixture-key") || strings.Contains(response.Body.String(), `"code":`) {
		t.Fatal("response leaked credentials or full source context")
	}
	for _, test := range []struct {
		role, body, csrf string
		status           int
	}{
		{"viewer", `{"kind":"search","query":"数据库"}`, "csrf-test-token", 403},
		{"operator", `{"kind":"search","query":"数据库"}`, "", 403},
		{"operator", `{"kind":"search","query":""}`, "csrf-test-token", 400},
		{"operator", `{"kind":"architecture","source":"injected"}`, "csrf-test-token", 400},
	} {
		loaded = false
		response = request(test.role, test.body, test.csrf)
		if response.Code != test.status || loaded {
			t.Fatalf("invalid request reached source/provider: %d %s", response.Code, response.Body)
		}
	}
}
