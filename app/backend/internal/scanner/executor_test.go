package scanner

import (
	"archive/tar"
	"archive/zip"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestDetectFileRoutesRepresentativeFormats(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		header   []byte
		expected string
	}{
		{name: "elf", filename: "sample", header: []byte{0x7f, 'E', 'L', 'F', 2}, expected: "elf64"},
		{name: "java class before fat Mach-O", filename: "Sample.class", header: []byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 61}, expected: "java-class"},
		{name: "Mach-O", filename: "sample", header: []byte{0xcf, 0xfa, 0xed, 0xfe}, expected: "macho-thin"},
		{name: "PYC", filename: "sample.pyc", header: append([]byte{0xcb, 0x0d, 0x0d, 0x0a}, make([]byte, 12)...), expected: "pyc"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "input")
			if err := os.WriteFile(path, test.header, 0o600); err != nil {
				t.Fatal(err)
			}
			actual, err := detectFile(path, test.filename)
			if err != nil {
				t.Fatal(err)
			}
			if actual != test.expected {
				t.Fatalf("detectFile() = %q, want %q", actual, test.expected)
			}
		})
	}
}

func TestDetectFileInspectsAPKContents(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "sample.apk")
	file, err := os.Create(filename)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(file)
	for name, body := range map[string]string{"AndroidManifest.xml": "manifest", "classes.dex": "dex\n035\x00"} {
		entry, createErr := writer.Create(name)
		if createErr != nil {
			t.Fatal(createErr)
		}
		if _, writeErr := entry.Write([]byte(body)); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	format, err := detectFile(filename, "sample.apk")
	if err != nil {
		t.Fatal(err)
	}
	if format != "apk" {
		t.Fatalf("detectFile() = %q, want apk", format)
	}
}

func TestTrivyUsesImageInputMode(t *testing.T) {
	args := trivyImageArgs("/cache", "/work/report.json", "/blobs/image.tar")
	if len(args) < 3 || args[0] != "image" || !slices.Contains(args, "--input") || !slices.Contains(args, "/blobs/image.tar") {
		t.Fatalf("trivyImageArgs() = %v", args)
	}
	if slices.Contains(args, "filesystem") {
		t.Fatalf("trivyImageArgs() unexpectedly enables filesystem mode: %v", args)
	}
}

func TestPrepareTrivyCacheLinksImmutableDatabasesIntoWritableRoot(t *testing.T) {
	databaseRoot := t.TempDir()
	for directory, files := range map[string][]string{
		"db":      {"metadata.json", "trivy.db"},
		"java-db": {"metadata.json", "trivy-java.db"},
	} {
		root := filepath.Join(databaseRoot, directory)
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, name := range files {
			if err := os.WriteFile(filepath.Join(root, name), []byte("fixture"), 0o400); err != nil {
				t.Fatal(err)
			}
		}
	}

	workDirectory := t.TempDir()
	cacheDirectory, err := prepareTrivyCache(databaseRoot, workDirectory)
	if err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{"db", "java-db"} {
		info, err := os.Lstat(filepath.Join(cacheDirectory, directory))
		if err != nil || info.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("cache database %s is not a symlink: info=%v err=%v", directory, info, err)
		}
	}
	if err := os.Mkdir(filepath.Join(cacheDirectory, "fanal"), 0o700); err != nil {
		t.Fatalf("writable Trivy cache root rejected fanal directory: %v", err)
	}
}

func TestPrepareTrivyCacheRejectsIncompleteDatabase(t *testing.T) {
	databaseRoot := t.TempDir()
	if err := os.Mkdir(filepath.Join(databaseRoot, "db"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareTrivyCache(databaseRoot, t.TempDir()); err == nil {
		t.Fatal("expected an incomplete vulnerability database to be rejected")
	}
}

func TestPrepareTrivyInputMaterializesOCIImageLayout(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "layout.tar")
	writeTrivyOCITar(t, archive, false)
	workDirectory := t.TempDir()

	input, err := prepareTrivyInput(context.Background(), archive, "oci-tar", workDirectory, 1<<20, 20)
	if err != nil {
		t.Fatal(err)
	}
	if input != filepath.Join(workDirectory, "oci-layout") {
		t.Fatalf("prepareTrivyInput() = %q", input)
	}
	for _, name := range []string{
		"oci-layout",
		"index.json",
		"blobs/sha256/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	} {
		info, err := os.Lstat(filepath.Join(input, filepath.FromSlash(name)))
		if err != nil || !info.Mode().IsRegular() {
			t.Fatalf("OCI member %s was not materialized: info=%v err=%v", name, info, err)
		}
	}
}

func TestPrepareTrivyInputRejectsOCILinks(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "layout.tar")
	writeTrivyOCITar(t, archive, true)
	if _, err := prepareTrivyInput(context.Background(), archive, "oci-tar", t.TempDir(), 1<<20, 20); err == nil {
		t.Fatal("expected an OCI layout symlink to be rejected")
	}
}

func TestPrepareTrivyInputRejectsOCITraversal(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "layout.tar")
	writeSingleTrivyTarMember(t, archive, "../outside", "escape")
	_, err := prepareTrivyInput(context.Background(), archive, "oci-tar", t.TempDir(), 1<<20, 20)
	if err == nil || !strings.Contains(err.Error(), "invalid OCI layout member") {
		t.Fatalf("prepareTrivyInput() error = %v, want invalid member rejection", err)
	}
}

func TestPrepareTrivyInputEnforcesOCILimits(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "layout.tar")
	writeTrivyOCITar(t, archive, false)
	if _, err := prepareTrivyInput(context.Background(), archive, "oci-tar", t.TempDir(), 1, 20); err == nil {
		t.Fatal("expected the OCI expanded byte limit to be enforced")
	}
	if _, err := prepareTrivyInput(context.Background(), archive, "oci-tar", t.TempDir(), 1<<20, 2); err == nil {
		t.Fatal("expected the OCI entry limit to be enforced")
	}
}

func TestCopyNWithContextStopsDuringCopy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	source := &cancelAfterFirstRead{
		reader: strings.NewReader(strings.Repeat("x", 128<<10)),
		cancel: cancel,
	}
	written, err := copyNWithContext(ctx, io.Discard, source, 128<<10)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("copyNWithContext() error = %v, want context cancellation", err)
	}
	if written >= 128<<10 {
		t.Fatalf("copyNWithContext() copied %d bytes after cancellation", written)
	}
}

func TestPrepareTrivyInputKeepsDockerSaveArchive(t *testing.T) {
	input := filepath.Join(t.TempDir(), "docker-save.tar")
	actual, err := prepareTrivyInput(context.Background(), input, "docker-tar", t.TempDir(), 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if actual != input {
		t.Fatalf("prepareTrivyInput() = %q, want %q", actual, input)
	}
}

func writeTrivyOCITar(t *testing.T, filename string, includeLink bool) {
	t.Helper()
	file, err := os.Create(filename)
	if err != nil {
		t.Fatal(err)
	}
	writer := tar.NewWriter(file)
	members := []struct {
		name string
		body string
	}{
		{name: "oci-layout", body: `{"imageLayoutVersion":"1.0.0"}`},
		{name: "index.json", body: `{"schemaVersion":2,"manifests":[]}`},
		{name: "blobs/sha256/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", body: `{}`},
	}
	for _, member := range members {
		if err := writer.WriteHeader(&tar.Header{Name: member.name, Mode: 0o400, Size: int64(len(member.body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte(member.body)); err != nil {
			t.Fatal(err)
		}
	}
	if includeLink {
		if err := writer.WriteHeader(&tar.Header{Name: "escape", Typeflag: tar.TypeSymlink, Linkname: "../outside"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func writeSingleTrivyTarMember(t *testing.T, filename, name, body string) {
	t.Helper()
	file, err := os.Create(filename)
	if err != nil {
		t.Fatal(err)
	}
	writer := tar.NewWriter(file)
	if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0o400, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

type cancelAfterFirstRead struct {
	reader io.Reader
	cancel context.CancelFunc
	reads  int
}

func (r *cancelAfterFirstRead) Read(buffer []byte) (int, error) {
	if len(buffer) > 1024 {
		buffer = buffer[:1024]
	}
	count, err := r.reader.Read(buffer)
	if r.reads == 0 {
		r.cancel()
	}
	r.reads++
	return count, err
}
