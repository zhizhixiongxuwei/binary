package app

import (
	"archive/zip"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCanonicalArchiveBundleOptions(t *testing.T) {
	options := archiveBundleOptions{Formats: []string{"json", "html"}, IncludeSources: true}
	if !canonicalArchiveBundleOptions(&options) {
		t.Fatal("valid archive bundle options rejected")
	}
	if strings.Join(options.Formats, ",") != "html,json" {
		t.Fatalf("formats were not canonicalized: %v", options.Formats)
	}
	for _, invalid := range []archiveBundleOptions{
		{},
		{Formats: []string{"pdf"}},
		{Formats: []string{"html", "html"}},
		{Formats: []string{"html", "json", "docx", "json"}},
	} {
		if canonicalArchiveBundleOptions(&invalid) {
			t.Fatalf("invalid archive bundle options accepted: %#v", invalid)
		}
	}
}

func TestArchiveBundleChildDirectoryIsPortable(t *testing.T) {
	for _, test := range []struct {
		path string
		want string
	}{
		{path: "../../CON", want: "_CON"},
		{path: `bin\\unsafe:name.exe`, want: "unsafe_name.exe"},
		{path: "目录/有 空格.class", want: "有_空格.class"},
	} {
		actual := archiveBundleChildDirectory(7, test.path, "12345678-abcd-4000-8000-123456789abc")
		if !strings.Contains(actual, test.want) {
			t.Errorf("archiveBundleChildDirectory(%q) = %q, want portable component %q", test.path, actual, test.want)
		}
		if strings.Contains(actual, "..") || strings.ContainsAny(actual, `/\\:`) {
			t.Errorf("archive bundle directory is unsafe: %q", actual)
		}
	}
}

func TestPortableArchiveSourcePathPreservesHierarchyAndAvoidsCollisions(t *testing.T) {
	left := portableArchiveSourcePath("src/unsafe:name.java", strings.Repeat("a", 64))
	right := portableArchiveSourcePath("src/unsafe?name.java", strings.Repeat("b", 64))
	if left == right {
		t.Fatalf("portable source paths collided: %q", left)
	}
	if !strings.HasPrefix(left, "src/unsafe_name__aaaaaaaa.java") {
		t.Fatalf("portable source path = %q", left)
	}
	for _, value := range []string{left, right} {
		if strings.ContainsAny(value, `\\:?*\"<>|`) || strings.Contains(value, "..") {
			t.Fatalf("portable source path contains a Windows-unsafe component: %q", value)
		}
	}
}

func TestBuildArchiveBundleIndexEscapesNames(t *testing.T) {
	manifest := archiveBundleManifest{
		Archive: archiveBundleManifestArchive{Filename: `<unsafe>.zip`, InputSHA256: strings.Repeat("a", 64)},
		Summary: archiveBundleManifestSummary{IncludedTasks: 1, ReportFiles: 1},
		Children: []archiveBundleManifestChild{{
			ArchivePath: `<member>.class`, TaskID: "task-1", Included: true,
			Reports: []archiveBundleManifestReport{{Format: "html", BundlePath: "children/task/report.html"}},
		}},
	}
	body := string(buildArchiveBundleIndex(manifest))
	for _, expected := range []string{"&lt;unsafe&gt;.zip", "&lt;member&gt;.class", `href="children/task/report.html"`} {
		if !strings.Contains(body, expected) {
			t.Fatalf("archive bundle index omitted %q: %s", expected, body)
		}
	}
	if strings.Contains(body, "<unsafe>") || strings.Contains(body, "<member>") {
		t.Fatal("archive bundle index contains unescaped input")
	}
}

func TestPublishArchiveBundleWritesVerifiedReportsAndSources(t *testing.T) {
	root := t.TempDir()
	reportRoot := filepath.Join(root, "reports")
	if err := os.MkdirAll(filepath.Join(reportRoot, ".staging"), 0o700); err != nil {
		t.Fatal(err)
	}
	reportBody := []byte("<html>report</html>")
	reportRelative := filepath.Join("reports", "task-1", "report-1.html")
	reportFilename := filepath.Join(root, reportRelative)
	if err := os.MkdirAll(filepath.Dir(reportFilename), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(reportFilename, reportBody, 0o600); err != nil {
		t.Fatal(err)
	}
	reportDigest := sha256.Sum256(reportBody)
	sourceBody := []byte("class Example {}")
	sourceFilename := filepath.Join(root, "source.java")
	if err := os.WriteFile(sourceFilename, sourceBody, 0o600); err != nil {
		t.Fatal(err)
	}
	sourceDigest := sha256.Sum256(sourceBody)
	prepared := preparedArchiveBundle{
		Manifest: archiveBundleManifest{
			Schema: archiveBundleSchema, GeneratedAt: time.Now().UTC(),
			Archive:  archiveBundleManifestArchive{ImportID: "import-1", Filename: "sample.zip"},
			Summary:  archiveBundleManifestSummary{CreatedTasks: 1, IncludedTasks: 1, ReportFiles: 1, SourceFiles: 1},
			Children: []archiveBundleManifestChild{{TaskID: "task-1", Included: true}},
		},
		Reports: []archiveBundleReportFile{{
			TaskID: "task-1", StorageKey: filepath.ToSlash(reportRelative),
			Manifest: archiveBundleManifestReport{Format: "html", SHA256: fmt.Sprintf("%x", reportDigest),
				SizeBytes: int64(len(reportBody)), BundlePath: "children/task-1/reports/report.html"},
		}},
		Sources: []archiveBundleSourceFile{{
			TaskID: "task-1", StorageKey: sourceFilename,
			Manifest: archiveBundleManifestSource{SHA256: fmt.Sprintf("%x", sourceDigest),
				SizeBytes: int64(len(sourceBody)), BundlePath: "children/task-1/sources/project-1/Example.java"},
		}},
	}
	service := taskService{storageRoot: root, reportRoot: reportRoot}
	relative, digest, size, err := service.publishArchiveBundle("import-1", "bundle-1", prepared)
	if err != nil {
		t.Fatal(err)
	}
	if len(digest) != sha256.Size || size <= 0 {
		t.Fatalf("invalid published bundle metadata: digest=%x size=%d", digest, size)
	}
	reader, err := zip.OpenReader(filepath.Join(reportRoot, filepath.FromSlash(relative)))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	contents := make(map[string]string)
	for _, file := range reader.File {
		body, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		value, err := io.ReadAll(body)
		body.Close()
		if err != nil {
			t.Fatal(err)
		}
		contents[file.Name] = string(value)
	}
	for name, expected := range map[string]string{
		"children/task-1/reports/report.html":            string(reportBody),
		"children/task-1/sources/project-1/Example.java": string(sourceBody),
	} {
		if contents[name] != expected {
			t.Errorf("ZIP entry %q = %q, want %q", name, contents[name], expected)
		}
	}
	for _, name := range []string{"manifest.json", "index.html"} {
		if contents[name] == "" {
			t.Errorf("ZIP entry %q is missing", name)
		}
	}
}
