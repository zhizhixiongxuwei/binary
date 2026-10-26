package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

func ptr[T any](v T) *T { return &v }

func TestSettingsEncryptedPersistence(t *testing.T) {
	dir := t.TempDir()
	m, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s := m.Get(); s.Enabled || s.Configured || s.Model != "deepseek-flash" || s.APIKeyMasked != "" {
		t.Fatalf("unexpected defaults: %+v", s)
	}
	secret := "test-private-api-key-never-return"
	s, err := m.Update(UpdateSettings{Enabled: ptr(true), APIKey: &secret})
	if err != nil {
		t.Fatal(err)
	}
	if !s.Configured || s.APIKeyMasked != "********" {
		t.Fatalf("unexpected safe settings: %+v", s)
	}
	for _, name := range []string{"llm.json", "llm-master.key"} {
		path := filepath.Join(dir, ".settings", name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), secret) {
			t.Fatal("plaintext API key on disk")
		}
		if runtime.GOOS != "windows" {
			info, _ := os.Stat(path)
			if info.Mode().Perm() != 0600 {
				t.Fatalf("unsafe mode: %v", info.Mode())
			}
		}
	}
	encoded, _ := json.Marshal(m.Snapshot())
	if strings.Contains(string(encoded), secret) {
		t.Fatal("snapshot JSON leaks API key")
	}
	m, err = New(dir)
	if err != nil {
		t.Fatal(err)
	}
	if m.Snapshot().APIKey != secret {
		t.Fatal("failed to decrypt saved key")
	}
	if _, err = m.Update(UpdateSettings{Model: ptr("custom-model"), APIKey: ptr("")}); err != nil {
		t.Fatal(err)
	}
	if m.Snapshot().APIKey != secret {
		t.Fatal("empty replacement must preserve key")
	}
	if _, err = m.Update(UpdateSettings{ClearAPIKey: true}); err != nil {
		t.Fatal(err)
	}
	m, err = New(dir)
	if err != nil {
		t.Fatal(err)
	}
	if m.Get().Configured || m.Snapshot().APIKey != "" {
		t.Fatal("key not cleared")
	}
}

func TestSettingsValidationAndAtomicity(t *testing.T) {
	m, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range []UpdateSettings{
		{BaseURL: ptr("https://key@example.com/v1")}, {BaseURL: ptr("https://example.com?token=key")},
		{BaseURL: ptr("ftp://example.com")}, {BaseURL: ptr("https://example.com/#x")},
		{APIKey: ptr("abc\r\ndef")}, {MaxInputChars: ptr(255)}, {TimeoutSeconds: ptr(601)},
		{MaxConcurrent: ptr(9)}, {MaxOutputTokens: ptr(127)}, {MaxOutputTokens: ptr(16385)},
		{Provider: ptr("unsupported")}, {APIKey: ptr("key"), ClearAPIKey: true},
	} {
		if _, err := m.Update(u); err == nil {
			t.Fatalf("accepted invalid update: %+v", u)
		}
	}
	if s := m.Get(); s.BaseURL != "https://api.deepseek.com" || s.Configured {
		t.Fatal("invalid update changed state")
	}
	if _, err := m.Update(UpdateSettings{BaseURL: ptr("http://localhost:1234/v1/"), TimeoutSeconds: ptr(600), MaxOutputTokens: ptr(16384), MaxInputChars: ptr(256)}); err != nil {
		t.Fatal(err)
	}
	if m.Get().BaseURL != "http://localhost:1234/v1" {
		t.Fatal("base URL not normalized")
	}
}

func TestConcurrentSettings(t *testing.T) {
	m, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				m.Get()
				m.Snapshot()
				if _, err := m.Update(UpdateSettings{MaxConcurrent: ptr(2)}); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
}

func TestSymlinkSettingsRejected(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dir, ".settings")); err != nil {
		t.Skip("symlinks unavailable")
	}
	if _, err := New(dir); err == nil {
		t.Fatal("accepted symlink storage")
	}
}

func testSnapshot(url string) Snapshot {
	s := defaults()
	s.Enabled = true
	s.BaseURL = url
	return Snapshot{Settings: s, APIKey: "test-key"}
}
func writeSSE(w http.ResponseWriter, text string) {
	w.Header().Set("Content-Type", "text/event-stream")
	data, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"index": 0, "delta": map[string]string{"content": text}, "finish_reason": "stop"}}})
	fmt.Fprintf(w, "data: %s\n\ndata: [DONE]\n\n", data)
}
func errorCode(t *testing.T, err error) string {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("expected safe error, got %v", err)
	}
	return e.Code
}

func TestStreamDeepSeekProtocol(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("bad upstream request")
		}
		var p completionRequest
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			t.Error(err)
		}
		if p.Model != "deepseek-flash" || p.MaxTokens != 4096 || !p.Stream || p.Thinking == nil || p.Thinking.Type != "disabled" {
			t.Errorf("bad completion settings: %+v", p)
		}
		if !strings.Contains(p.Messages[0].Content, "不可信数据") {
			t.Error("missing source trust boundary")
		}
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		io.WriteString(w, ": keepalive\n\ndata: {\"choices\":[{\"index\":0,\"delta\":{\"reasoning_content\":\"PRIVATE_REASONING\"}}]}\n\n")
		io.WriteString(w, "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"源码\"}}]}\n\n")
		io.WriteString(w, "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"解释 L1\"},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n")
	}))
	defer server.Close()
	var text strings.Builder
	if err := Stream(context.Background(), testSnapshot(server.URL+"/v1"), "L1 func main(){}", func(s string) error { text.WriteString(s); return nil }); err != nil {
		t.Fatal(err)
	}
	if text.String() != "源码解释 L1" {
		t.Fatalf("unexpected output %q", text.String())
	}
}

func TestCompatibleAndTestWhileDisabled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if _, ok := body["thinking"]; ok {
			t.Error("sent vendor field to compatible provider")
		}
		writeSSE(w, "连接成功")
	}))
	defer server.Close()
	m, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Update(UpdateSettings{BaseURL: ptr(server.URL), Provider: ptr("openai-compatible"), APIKey: ptr("test-key")}); err != nil {
		t.Fatal(err)
	}
	if err = m.Test(context.Background()); err != nil {
		t.Fatal(err)
	}
	if m.Get().Enabled {
		t.Fatal("test enabled source transmission")
	}
}

func TestProviderErrorsDoNotLeak(t *testing.T) {
	for _, status := range []int{401, 429, 500, 302} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
				io.WriteString(w, "sensitive upstream response test-key")
			}))
			defer server.Close()
			err := Stream(context.Background(), testSnapshot(server.URL), "source", func(string) error { return nil })
			if err == nil || strings.Contains(err.Error(), "sensitive") || strings.Contains(err.Error(), "test-key") {
				t.Fatalf("unsafe error: %v", err)
			}
			if status == 429 && errorCode(t, err) != "llm_rate_limited" {
				t.Fatal(err)
			}
		})
	}
}

func TestStreamCancellation(t *testing.T) {
	seen := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(seen)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err := Stream(ctx, testSnapshot(server.URL), "source", func(string) error { return nil })
	if errorCode(t, err) != "llm_timeout" || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	select {
	case <-seen:
	case <-time.After(time.Second):
		t.Fatal("provider request was not cancelled")
	}
}

func TestStreamRejectsPartialAndLimits(t *testing.T) {
	cases := []struct{ name, body, code string }{
		{"partial", "data: {\"choices\":[{\"delta\":{\"content\":\"partial\"}}]}\n\n", "llm_response_incomplete"},
		{"malformed", "data: invalid\n\ndata: [DONE]\n\n", "llm_invalid_response"},
		{"empty", "data: [DONE]\n\n", "llm_empty_response"},
		{"tokenlimit", "data: {\"choices\":[{\"delta\":{\"content\":\"partial\"},\"finish_reason\":\"length\"}]}\n\ndata: [DONE]\n\n", "llm_output_limit"},
		{"oversize", "data: " + strings.Repeat("x", maxEventBytes+1) + "\n\n", "llm_stream_failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := readStream(context.Background(), strings.NewReader(tc.body), func(string) error { return nil })
			if errorCode(t, err) != tc.code {
				t.Fatalf("wrong code %s", errorCode(t, err))
			}
		})
	}
	w := httptest.NewRecorder()
	writeSSE(w, strings.Repeat("中", MaxOutputChars+1))
	var output strings.Builder
	err := readStream(context.Background(), strings.NewReader(w.Body.String()), func(s string) error { output.WriteString(s); return nil })
	if errorCode(t, err) != "llm_output_limit" || utf8.RuneCountInString(output.String()) != MaxOutputChars {
		t.Fatal("output character bound failed")
	}
}

func TestDisabledAndInputBound(t *testing.T) {
	s := testSnapshot("http://127.0.0.1:1")
	s.Enabled = false
	if code := errorCode(t, Stream(context.Background(), s, "source", func(string) error { return nil })); code != "llm_disabled" {
		t.Fatal(code)
	}
	s.Enabled = true
	if code := errorCode(t, Stream(context.Background(), s, strings.Repeat("中", s.MaxInputChars+8193), func(string) error { return nil })); code != "llm_input_too_large" {
		t.Fatal(code)
	}
}
