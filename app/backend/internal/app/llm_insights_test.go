package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"

	"binaryscan.local/backend/internal/llm"
)

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
	service.loadProject = func(ctx context.Context, target explanationTarget, limit int) (insightContext, error) {
		if target.TaskID != "task" || target.ProjectID != "project" || limit != 512 {
			t.Fatalf("wrong source identity or settings: %+v %d", target, limit)
		}
		loaded = true
		return insightFixtureContext(), nil
	}
	service.stream = func(ctx context.Context, settings llm.Snapshot, prompt string, delta func(string) error) error {
		if !strings.Contains(prompt, "actual.c") || !strings.Contains(prompt, "数据库查询") || settings.APIKey != "test-fixture-key" {
			t.Fatal("request did not reuse saved settings and source")
		}
		return delta(`{"summary":"查询匹配","matches":[{"fileId":"file","name":"query","startLine":10,"endLine":12,"reason":"SQL调用","evidence":"query()"}]}`)
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
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil || len(payload.Result.Matches) != 1 || !payload.Coverage.Truncated {
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
