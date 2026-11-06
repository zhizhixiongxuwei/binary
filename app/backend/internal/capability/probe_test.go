package capability

import (
	"archive/zip"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"binaryscan.local/backend/internal/config"
)

func databaseFixture(t *testing.T, metadata string, content []byte) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "db"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "db", "trivy.db"), content, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "db", "metadata.json"), []byte(metadata), 0600); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestDatabaseProbeRequiresReadableNonemptyFileCompatibleMetadata(t *testing.T) {
	date := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	for _, item := range []struct {
		name, metadata string
		content        []byte
		available      bool
	}{
		{"healthy", fmt.Sprintf(`{"Version":2,"UpdatedAt":%q}`, date), []byte("database"), true},
		{"empty", fmt.Sprintf(`{"Version":2,"UpdatedAt":%q}`, date), nil, false},
		{"invalid-json", `{`, []byte("database"), false},
		{"wrong-schema", fmt.Sprintf(`{"Version":1,"UpdatedAt":%q}`, date), []byte("database"), false},
		{"missing-time", `{"Version":2}`, []byte("database"), false},
		{"future-time", `{"Version":2,"UpdatedAt":"2099-01-01T00:00:00Z"}`, []byte("database"), false},
	} {
		t.Run(item.name, func(t *testing.T) {
			result := ProbeDatabase(databaseFixture(t, item.metadata, item.content), "db", "trivy.db", "trivy-db", 2)
			if (result.Status == "available") != item.available {
				t.Fatalf("probe=%+v", result)
			}
			if !item.available && result.Error == "" {
				t.Fatal("failed probe must explain the failure")
			}
		})
	}
	missing := ProbeDatabase(t.TempDir(), "db", "trivy.db", "trivy-db", 2)
	if missing.Status != "unavailable" {
		t.Fatalf("missing=%+v", missing)
	}
	root := databaseFixture(t, fmt.Sprintf(`{"Version":2,"UpdatedAt":%q}`, date), []byte("database"))
	if err := os.Rename(filepath.Join(root, "db", "trivy.db"), filepath.Join(root, "db", "target.db")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target.db", filepath.Join(root, "db", "trivy.db")); err == nil {
		if result := ProbeDatabase(root, "db", "trivy.db", "trivy-db", 2); result.Status != "unavailable" {
			t.Fatal("probe accepted a symlink the real scanner rejects")
		}
	}
}

func TestCheckerProbeValidatesIdentityWithoutRunningAnalysis(t *testing.T) {
	for _, item := range []struct {
		body     string
		code     int
		expected string
	}{
		{`{"status":"ok","checker":"java"}`, 200, "available"},
		{`{"status":"ok","checker":"python"}`, 200, "unavailable"},
		{`{"status":"ok","checker":"java"}`, 503, "unavailable"},
		{`invalid`, 200, "unavailable"},
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/healthz" || r.Method != "GET" {
				t.Errorf("unexpected analysis request %s %s", r.Method, r.URL.Path)
			}
			w.WriteHeader(item.code)
			_, _ = w.Write([]byte(item.body))
		}))
		result := probeChecker(context.Background(), "java", server.URL, time.Now())
		server.Close()
		if result.Status != item.expected || result.Version != "" {
			t.Fatalf("result=%+v", result)
		}
	}
	result := probeChecker(context.Background(), "java", "", time.Now())
	if result.Status != "unknown" {
		t.Fatalf("unconfigured=%+v", result)
	}
}

func TestJarVersionReadsActualManifestAndRejectsMissingVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tool.jar")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	jar := zip.NewWriter(file)
	entry, err := jar.Create("META-INF/MANIFEST.MF")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = entry.Write([]byte("Implementation-Version: 1.12.0\r\n"))
	_ = jar.Close()
	_ = file.Close()
	version, err := jarVersion(path)
	if err != nil || version != "1.12.0" {
		t.Fatalf("version=%s error=%v", version, err)
	}
	if _, err := jarVersion(filepath.Join(t.TempDir(), "missing.jar")); err == nil {
		t.Fatal("missing jar cannot pass")
	}
}

func TestMissingToolsCannotReportAvailability(t *testing.T) {
	root := t.TempDir()
	for _, role := range []string{"scanner", "native-decompiler", "jvm-decompiler", "pyc-decompiler"} {
		cfg := config.Config{Role: role, Worker: config.Worker{TrivyPath: filepath.Join(root, "missing"), TrivyCacheRoot: root, GhidraPath: filepath.Join(root, "missing"), JavaPath: filepath.Join(root, "missing"), VineflowerJar: filepath.Join(root, "missing.jar"), CFRJar: filepath.Join(root, "missing.jar"), JADXJar: filepath.Join(root, "missing.jar"), PYCDCPath: filepath.Join(root, "missing")}}
		report := Collect(context.Background(), cfg)
		if len(report.Analyzers) == 0 {
			t.Fatal("missing report")
		}
		for _, analyzer := range report.Analyzers {
			if analyzer.Status == "available" {
				t.Fatalf("missing tool reported available: %+v", analyzer)
			}
			if strings.Contains(analyzer.Detail, root) {
				t.Fatal("raw process failure leaked into detail")
			}
		}
	}
}
