package app

import (
	"archive/zip"
	"bytes"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestSourceArchivePreservesEntriesAndCleansStaging(t *testing.T) {
	root := t.TempDir()
	service := taskService{storageRoot: root, reportRoot: filepath.Join(root, "reports")}
	staging := filepath.Join(service.reportRoot, ".staging")
	for filename, body := range map[string]string{
		"projects/jvm/java/pkg/Example.java":   "package pkg;\n",
		"projects/jvm/java/jvm-source-map.tsv": "map\n",
		"projects/jvm/java/project.json":       "{}",
		"projects/native/c/sample.c":           "int value;\n",
	} {
		path := filepath.Join(root, filepath.FromSlash(filename))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(staging, 0o700); err != nil {
		t.Fatal(err)
	}

	projects := []sourceProjectPath{
		{id: "java", sourceKind: "jvm", storageKey: "java"},
		{id: "c", sourceKind: "native", storageKey: "c"},
	}
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	service.sendSourceArchive(c, projects, true, "test.zip")
	if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != "application/zip" ||
		recorder.Header().Get("Content-Length") != strconv.Itoa(recorder.Body.Len()) ||
		recorder.Header().Get("Content-Disposition") != "attachment; filename=\"test.zip\"" {
		t.Fatalf("unexpected response %d, headers %v", recorder.Code, recorder.Header())
	}
	archive, err := zip.NewReader(bytes.NewReader(recorder.Body.Bytes()), int64(recorder.Body.Len()))
	if err != nil {
		t.Fatal(err)
	}
	got := make(map[string]string)
	for _, file := range archive.File {
		entry, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(entry)
		if closeErr := entry.Close(); err != nil || closeErr != nil {
			t.Fatalf("read ZIP entry %q: %v, %v", file.Name, err, closeErr)
		}
		got[file.Name] = string(body)
	}
	want := map[string]string{
		"java/pkg/Example.java":   "package pkg;\n",
		"java/jvm-source-map.tsv": "map\n",
		"c/sample.c":              "int value;\n",
		"all-functions.c":         "\n\n/* ===== c/sample.c ===== */\nint value;\n",
	}
	if !maps.Equal(got, want) {
		t.Fatalf("unexpected ZIP contents %#v", got)
	}
	assertSourceArchiveStagingEmpty(t, staging)

	// Fail after the first project was written. The partial archive must not
	// reach the client or remain in the staging directory.
	projects[1].storageKey = "missing"
	recorder = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	service.sendSourceArchive(c, projects, true, "test.zip")
	if recorder.Code != http.StatusInternalServerError || recorder.Body.String() != "{\"error\":\"source_export_failed\"}" ||
		recorder.Header().Get("Content-Disposition") != "" {
		t.Fatalf("unexpected failure response %d: %s", recorder.Code, recorder.Body.String())
	}
	assertSourceArchiveStagingEmpty(t, staging)
}

func assertSourceArchiveStagingEmpty(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("unexpected staging directory contents %v, error %v", entries, err)
	}
}
