package app

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"binaryscan.local/backend/internal/llm"
	"github.com/gin-gonic/gin"
)

type llmRecoveryTestConnector struct{ connection *llmRecoveryTestConnection }

func (c llmRecoveryTestConnector) Connect(context.Context) (driver.Conn, error) {
	return c.connection, nil
}
func (c llmRecoveryTestConnector) Driver() driver.Driver { return llmRecoveryTestDriver{c.connection} }

type llmRecoveryTestDriver struct{ connection *llmRecoveryTestConnection }

func (d llmRecoveryTestDriver) Open(string) (driver.Conn, error) { return d.connection, nil }

type llmRecoveryTestConnection struct {
	query    string
	calls    int
	deadline bool
	err      error
}

func (c *llmRecoveryTestConnection) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (c *llmRecoveryTestConnection) Close() error { return nil }
func (c *llmRecoveryTestConnection) Begin() (driver.Tx, error) {
	return nil, errors.New("unexpected transaction")
}
func (c *llmRecoveryTestConnection) ExecContext(ctx context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	c.query, c.calls = query, c.calls+1
	_, c.deadline = ctx.Deadline()
	return driver.RowsAffected(2), c.err
}

func TestLLMStartupRecoveryMustCompleteBeforeServing(t *testing.T) {
	for _, failure := range []error{nil, errors.New("database temporarily unavailable")} {
		connection := &llmRecoveryTestConnection{err: failure}
		db := sql.OpenDB(llmRecoveryTestConnector{connection})
		service, err := newLLMService(&taskService{db: db, storageRoot: t.TempDir()})
		db.Close()
		if connection.calls != 1 || connection.query != recoverInterruptedExplanationsSQL || !connection.deadline {
			t.Fatalf("startup skipped bounded recovery: %+v", connection)
		}
		if failure == nil && (err != nil || service == nil) {
			t.Fatalf("successful recovery prevented startup: %v", err)
		}
		if failure != nil && (err == nil || service != nil || !errors.Is(err, failure)) {
			t.Fatalf("failed recovery allowed startup: service=%v err=%v", service, err)
		}
	}
}

type memoryExplanations struct {
	mu               sync.Mutex
	items            []explanationRecord
	finishContextErr error
}

func (r *memoryExplanations) List(_ context.Context, target explanationTarget) ([]explanationRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	items := []explanationRecord{}
	for _, item := range r.items {
		if item.TaskID == target.TaskID && item.ProjectID == target.ProjectID && item.FileID == target.FileID {
			items = append(items, item)
		}
	}
	return items, nil
}
func (r *memoryExplanations) FindRequest(ctx context.Context, target explanationTarget, id string) (explanationRecord, error) {
	items, _ := r.List(ctx, target)
	for _, item := range items {
		if item.ID == id {
			return item, nil
		}
	}
	return explanationRecord{}, sql.ErrNoRows
}
func (r *memoryExplanations) FindCache(ctx context.Context, target explanationTarget, key string) (explanationRecord, error) {
	items, _ := r.List(ctx, target)
	for _, item := range items {
		if item.CacheKey == key && item.Status == "completed" {
			return item, nil
		}
	}
	return explanationRecord{}, sql.ErrNoRows
}
func (r *memoryExplanations) Insert(_ context.Context, item explanationRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.items = append(r.items, item)
	return nil
}
func (r *memoryExplanations) Finish(ctx context.Context, item explanationRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.finishContextErr = ctx.Err()
	for index := range r.items {
		if r.items[index].ID == item.ID {
			r.items[index] = item
			return nil
		}
	}
	return sql.ErrNoRows
}

func llmTestPointer[T any](value T) *T { return &value }
func testExplanationSource(content string) explanationSource {
	return explanationSource{sourceFileRecord: sourceFileRecord{ID: "file", ProjectID: "project", LogicalPath: "hello.c", Language: "c", SHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(content))), SizeBytes: int64(len(content))}, Content: content}
}
func newTestLLMService(t *testing.T) (*llmService, *memoryExplanations, *explanationSource) {
	t.Helper()
	manager, err := llm.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, err = manager.Update(llm.UpdateSettings{Enabled: llmTestPointer(true), APIKey: llmTestPointer("test-fixture-key"), MaxInputChars: llmTestPointer(512)})
	if err != nil {
		t.Fatal(err)
	}
	repository := &memoryExplanations{}
	source := testExplanationSource("int main() {\n  return 0;\n}\n")
	service := &llmService{manager: manager, repository: repository, loadSource: func(context.Context, explanationTarget) (explanationSource, error) { return source, nil }, stream: func(_ context.Context, _ llm.Snapshot, _ string, delta func(string) error) error {
		return delta("返回值为零 [L2]。")
	}}
	return service, repository, &source
}
func llmTestRouter(service *llmService, role string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(originGuard([]string{"http://localhost"}))
	router.Use(func(c *gin.Context) {
		c.Set("currentUser", currentUser{ID: 1, Role: role, CSRFToken: "csrf-test-token"})
		c.Next()
	})
	registerLLMRoutes(router.Group("/api/v1"), newAuthService(nil), service)
	return router
}

const testExplanationsURL = "/api/v1/tasks/task/projects/project/files/file/explanations"

func explainTestRequest(ctx context.Context, router http.Handler, id string, extra string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, testExplanationsURL, strings.NewReader(`{"scope":"file","requestId":"`+id+`"`+extra+`}`)).WithContext(ctx)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", "csrf-test-token")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

func TestExplanationSourceIntegrity(t *testing.T) {
	root := t.TempDir()
	source := testExplanationSource("int main() {}\n")
	filename := filepath.Join(root, source.LogicalPath)
	if err := os.WriteFile(filename, []byte(source.Content), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readExplanationSource(root, source.sourceFileRecord); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*sourceFileRecord){
		func(file *sourceFileRecord) { file.LogicalPath = "../outside.c" },
		func(file *sourceFileRecord) { file.SHA256 = strings.Repeat("0", 64) },
		func(file *sourceFileRecord) { file.SizeBytes++ },
	} {
		file := source.sourceFileRecord
		mutate(&file)
		if _, err := readExplanationSource(root, file); err == nil {
			t.Fatalf("accepted invalid source: %+v", file)
		}
	}
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "hello.c"), []byte(source.Content), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	file := source.sourceFileRecord
	file.LogicalPath = "link/hello.c"
	if _, err := readExplanationSource(root, file); err == nil {
		t.Fatal("accepted directory symlink")
	}
}

func TestExplanationSelectionAndLimits(t *testing.T) {
	source := testExplanationSource("第一行\r\nsecond\r\nthird")
	request := explanationRequest{Scope: "selection", StartLine: llmTestPointer(2), EndLine: llmTestPointer(2)}
	prompt, start, end, err := explanationInput(source, request, 6)
	if err != nil || start != 2 || end != 2 || !strings.Contains(prompt, "L2: second") || strings.Contains(prompt, "第一行") || strings.Contains(prompt, "third") {
		t.Fatalf("unexpected selected prompt: %q (%d,%d,%v)", prompt, start, end, err)
	}
	if _, _, _, err := explanationInput(source, request, 5); safeLLMError(err).Code != "llm_input_too_large" {
		t.Fatalf("oversize error: %v", err)
	}
	request.EndLine = llmTestPointer(4)
	if _, _, _, err := explanationInput(source, request, 100); safeLLMError(err).Code != "llm_invalid_range" {
		t.Fatalf("range error: %v", err)
	}
	request = explanationRequest{Scope: "file", StartLine: llmTestPointer(1)}
	if _, _, _, err := explanationInput(source, request, 100); err == nil {
		t.Fatal("file scope accepted line range")
	}
	request = explanationRequest{Scope: "file"}
	if _, _, _, err := explanationInput(testExplanationSource("中文"), request, 2); err != nil {
		t.Fatal("characters counted as bytes", err)
	}
}

func TestExplanationStreamCacheRegenerateAndStale(t *testing.T) {
	service, repository, source := newTestLLMService(t)
	router := llmTestRouter(service, "operator")
	calls := 0
	service.stream = func(ctx context.Context, settings llm.Snapshot, prompt string, delta func(string) error) error {
		calls++
		if !strings.Contains(prompt, "L2:   return 0;") {
			t.Error("server source not used")
		}
		return delta("解释 [L2]")
	}
	for index, extra := range []string{"", "", `,"regenerate":true`} {
		id := fmt.Sprintf("11111111-1111-4111-8111-%012d", index+1)
		response := explainTestRequest(context.Background(), router, id, extra)
		if response.Code != 200 || !strings.Contains(response.Body.String(), "event: meta") || !strings.Contains(response.Body.String(), "event: done") {
			t.Fatalf("stream failed: %d %s", response.Code, response.Body.String())
		}
		if index == 1 && !strings.Contains(response.Body.String(), `"cacheHit":true`) {
			t.Fatal("cached response not marked")
		}
	}
	if calls != 2 || len(repository.items) != 2 {
		t.Fatalf("calls=%d history=%d", calls, len(repository.items))
	}
	// Retrying the same request ID reuses its completed result even with regenerate.
	response := explainTestRequest(context.Background(), router, "11111111-1111-4111-8111-000000000003", `,"regenerate":true`)
	if response.Code != 200 || calls != 2 {
		t.Fatal("duplicate request billed again")
	}
	*source = testExplanationSource("changed")
	response = httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, testExplanationsURL, nil))
	if response.Code != 200 || !strings.Contains(response.Body.String(), `"stale":true`) {
		t.Fatalf("missing stale: %s", response.Body.String())
	}
	response = explainTestRequest(context.Background(), router, "11111111-1111-4111-8111-000000000004", `,"sourceSha256":"old"`)
	if response.Code != 409 || !strings.Contains(response.Body.String(), "llm_source_changed") || calls != 2 {
		t.Fatal("changed preview was sent", response.Body.String())
	}
}

func TestExplanationCancellationPersistsPartialText(t *testing.T) {
	service, repository, _ := newTestLLMService(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	service.stream = func(ctx context.Context, _ llm.Snapshot, _ string, delta func(string) error) error {
		if err := delta("partial"); err != nil {
			return err
		}
		cancel()
		<-ctx.Done()
		return ctx.Err()
	}
	response := explainTestRequest(ctx, llmTestRouter(service, "operator"), "11111111-1111-4111-8111-000000000001", "")
	if response.Code != 200 || len(repository.items) != 1 || repository.items[0].Status != "cancelled" || repository.items[0].Text != "partial" || repository.finishContextErr != nil {
		t.Fatalf("cancel save: %s %+v, ctx=%v", response.Body.String(), repository.items, repository.finishContextErr)
	}
	if service.active != 0 {
		t.Fatal("cancel leaked concurrency slot")
	}
}

func TestExplanationFailureAndConcurrency(t *testing.T) {
	for _, failure := range []error{context.DeadlineExceeded, &llm.Error{Code: "llm_rate_limited", Message: "稍后重试", HTTPStatus: 429}, errors.New("SECRET raw provider error")} {
		service, repository, _ := newTestLLMService(t)
		service.stream = func(context.Context, llm.Snapshot, string, func(string) error) error { return failure }
		response := explainTestRequest(context.Background(), llmTestRouter(service, "operator"), "11111111-1111-4111-8111-000000000001", "")
		if !strings.Contains(response.Body.String(), "event: error") || strings.Contains(response.Body.String(), "SECRET") || repository.items[0].Status != "failed" || service.active != 0 {
			t.Fatalf("failure not safe: %s", response.Body.String())
		}
	}
	service, repository, _ := newTestLLMService(t)
	service.active = service.manager.Get().MaxConcurrent
	response := explainTestRequest(context.Background(), llmTestRouter(service, "operator"), "11111111-1111-4111-8111-000000000001", "")
	if response.Code != 429 || len(repository.items) != 0 {
		t.Fatalf("busy: %d %s", response.Code, response.Body.String())
	}
}

func TestExplanationPermissionsCSRFOriginAndNoArbitraryCode(t *testing.T) {
	service, repository, _ := newTestLLMService(t)
	for _, test := range []struct {
		role, method, path, csrf, origin, body string
		status                                 int
	}{
		{"reader", "GET", testExplanationsURL, "", "", "", 200},
		{"reader", "GET", "/api/v1/admin/llm/settings", "", "", "", 403},
		{"operator", "GET", "/api/v1/admin/llm/settings", "", "", "", 403},
		{"administrator", "GET", "/api/v1/admin/llm/settings", "", "", "", 200},
		{"reader", "POST", testExplanationsURL, "csrf-test-token", "", `{}`, 403},
		{"operator", "POST", testExplanationsURL, "", "", `{}`, 403},
		{"operator", "POST", testExplanationsURL, "wrong", "", `{}`, 403},
		{"operator", "POST", testExplanationsURL, "csrf-test-token", "https://evil.invalid", `{}`, 403},
		{"operator", "POST", testExplanationsURL, "csrf-test-token", "", `{"scope":"file","requestId":"11111111-1111-4111-8111-000000000001","content":"do not accept"}`, 400},
	} {
		request := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
		request.Header.Set("X-CSRF-Token", test.csrf)
		request.Header.Set("Origin", test.origin)
		response := httptest.NewRecorder()
		llmTestRouter(service, test.role).ServeHTTP(response, request)
		if response.Code != test.status {
			t.Fatalf("%s %s %s got %d: %s", test.role, test.method, test.path, response.Code, response.Body.String())
		}
		if strings.Contains(response.Body.String(), "test-fixture-key") {
			t.Fatal("key disclosed")
		}
	}
	if len(repository.items) != 0 {
		t.Fatal("rejected requests created records")
	}
	status := httptest.NewRecorder()
	llmTestRouter(service, "reader").ServeHTTP(status, httptest.NewRequest("GET", "/api/v1/llm/status", nil))
	var dto map[string]any
	if err := json.Unmarshal(status.Body.Bytes(), &dto); err != nil {
		t.Fatal(err)
	}
	if _, ok := dto["apiKeyMasked"]; ok {
		t.Fatal("status should not expose admin key metadata")
	}
}

func TestExplanationRealProviderStream(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" {
			t.Errorf("path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"第一段\"}}]}\n\n")
		w.(http.Flusher).Flush()
		fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\" [L2]\"}}]}\n\ndata: [DONE]\n\n")
	}))
	defer provider.Close()
	service, repository, _ := newTestLLMService(t)
	if _, err := service.manager.Update(llm.UpdateSettings{BaseURL: &provider.URL, Provider: llmTestPointer("openai-compatible")}); err != nil {
		t.Fatal(err)
	}
	service.stream = llm.Stream
	response := explainTestRequest(context.Background(), llmTestRouter(service, "operator"), "11111111-1111-4111-8111-000000000001", "")
	if response.Code != 200 || len(repository.items) != 1 || repository.items[0].Status != "completed" || repository.items[0].Text != "第一段 [L2]" {
		t.Fatalf("provider integration: %s %+v", response.Body.String(), repository.items)
	}
}

func TestExplanationProviderCancellation(t *testing.T) {
	started := make(chan struct{})
	cancelled := make(chan struct{})
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"partial\"}}]}\n\n")
		w.(http.Flusher).Flush()
		close(started)
		select {
		case <-r.Context().Done():
			close(cancelled)
		case <-time.After(5 * time.Second):
		}
	}))
	defer provider.Close()
	service, repository, _ := newTestLLMService(t)
	if _, err := service.manager.Update(llm.UpdateSettings{BaseURL: &provider.URL, Provider: llmTestPointer("openai-compatible")}); err != nil {
		t.Fatal(err)
	}
	service.stream = llm.Stream
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan struct{})
	router := llmTestRouter(service, "operator")
	go func() {
		defer close(finished)
		explainTestRequest(ctx, router, "11111111-1111-4111-8111-000000000001", "")
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("provider not started")
	}
	cancel()
	select {
	case <-cancelled:
	case <-time.After(3 * time.Second):
		t.Fatal("provider context not cancelled")
	}
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("handler stuck")
	}
	if len(repository.items) != 1 || repository.items[0].Status != "cancelled" {
		t.Fatalf("cancelled history: %+v", repository.items)
	}
}

func TestExplanationExtendsNormalHTTPWriteDeadline(t *testing.T) {
	service, _, _ := newTestLLMService(t)
	service.stream = func(_ context.Context, _ llm.Snapshot, _ string, delta func(string) error) error {
		time.Sleep(80 * time.Millisecond)
		return delta("after normal HTTP deadline")
	}
	server := httptest.NewUnstartedServer(llmTestRouter(service, "operator"))
	server.Config.WriteTimeout = 20 * time.Millisecond
	server.Start()
	defer server.Close()
	request, err := http.NewRequest("POST", server.URL+testExplanationsURL, strings.NewReader(`{"scope":"file","requestId":"11111111-1111-4111-8111-000000000001"}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-CSRF-Token", "csrf-test-token")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var body strings.Builder
	if _, err := io.Copy(&body, response.Body); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body.String(), "event: done") {
		t.Fatalf("SSE was cut off by normal HTTP deadline: %s", body.String())
	}
}
