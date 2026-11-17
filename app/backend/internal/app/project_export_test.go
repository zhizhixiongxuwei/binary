package app

import (
	"archive/zip"
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestProjectExportCompletesBeyondOrdinaryWriteTimeout(t *testing.T) {
	var body bytes.Buffer
	archive := zip.NewWriter(&body)
	entry, _ := archive.Create("diagnostics.json")
	_, _ = entry.Write([]byte(`{"diagnostics":["preserved tool output"]}`))
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.GET("/export", func(c *gin.Context) {
		if err := setProjectExportDeadline(c.Writer); err != nil {
			t.Error(err)
			return
		}
		// Stand in for building a project larger than the ordinary API deadline.
		time.Sleep(80 * time.Millisecond)
		c.Data(http.StatusOK, "application/zip", body.Bytes())
	})
	server := httptest.NewUnstartedServer(router)
	server.Config.WriteTimeout = 20 * time.Millisecond
	server.Start()
	defer server.Close()
	response, err := server.Client().Get(server.URL + "/export")
	if err != nil {
		t.Fatalf("export cut off by ordinary API timeout: %v", err)
	}
	defer response.Body.Close()
	got, err := io.ReadAll(response.Body)
	if err != nil || !bytes.Equal(got, body.Bytes()) {
		t.Fatalf("truncated project ZIP: length=%d err=%v", len(got), err)
	}
	if _, err := zip.NewReader(bytes.NewReader(got), int64(len(got))); err != nil {
		t.Fatalf("invalid ZIP after download: %v", err)
	}
}

func TestProjectExportRejectsTraversalAndLinkedParents(t *testing.T) {
	root := t.TempDir()
	filename := filepath.Join(root, "nested", "checker-response.json")
	if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, []byte(`{"diagnostics":["parse failed"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := exportStoragePath(root, "nested/checker-response.json"); err != nil || got != filename {
		t.Fatalf("valid evidence unavailable: %q %v", got, err)
	}
	for _, key := range []string{"../secret", "/etc/passwd", "nested/../../secret"} {
		if _, err := exportStoragePath(root, key); err == nil {
			t.Fatalf("accepted %q", key)
		}
	}
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "linked")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := exportStoragePath(root, "linked/secret"); err == nil {
		t.Fatal("followed a linked parent directory")
	}
}

func TestProjectExportNamesCannotInjectZipPathsOrHeaders(t *testing.T) {
	for _, name := range []string{"../../escape", ".", "..", "", "x\r\nContent-Type:evil", `x\y`, "正常报告"} {
		got := exportName(name)
		if got == "" || got == "." || got == ".." || strings.ContainsAny(got, "/\\\r\n:\"") {
			t.Fatalf("unsafe name %q from %q", got, name)
		}
	}
}
