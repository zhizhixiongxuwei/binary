package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWorkspaceRejectsEscapeAndPublishesImmutableRunDirectory(t *testing.T) {
	root := t.TempDir()
	workspace, err := NewWorkspace(filepath.Join(root, "work"), "run-1", 1024)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = workspace.Cleanup() })
	if err := workspace.WriteFile("../escape.c", "c", strings.NewReader("bad")); err == nil {
		t.Fatal("expected path traversal to be rejected")
	}
	if err := workspace.WriteFile("src/main.c", "c", strings.NewReader("int main(void) { return 0; }")); err != nil {
		t.Fatal(err)
	}
	publication, err := workspace.PublishProject(filepath.Join(root, "projects"), "project-1", Manifest{
		RunID: "run-1", InputBlobID: "blob-1", InputSHA256: strings.Repeat("a", 64), InputPath: "sample.elf",
		Kind: "native", Language: "c", Quality: "source", ToolName: "test", ToolVersion: "1",
	})
	if err != nil {
		t.Fatal(err)
	}
	destination := publication.Root
	if publication.Manifest.Version != "project-v2" || publication.Manifest.ProjectID != "project-1" ||
		len(publication.Manifest.Files) != 1 || publication.Manifest.Files[0].ID == "" ||
		publication.Manifest.Files[0].LineCount != 1 || len(publication.Manifest.Files[0].SHA256) != 64 {
		t.Fatalf("unexpected publication manifest: %#v", publication.Manifest)
	}
	body, err := os.ReadFile(filepath.Join(destination, "project.json"))
	if err != nil {
		t.Fatal(err)
	}
	var persisted Manifest
	if err := json.Unmarshal(body, &persisted); err != nil || persisted.ProjectID != "project-1" {
		t.Fatalf("invalid persisted manifest: value=%#v error=%v", persisted, err)
	}
	for _, relative := range []string{"project.json", "src/main.c"} {
		info, err := os.Stat(filepath.Join(destination, relative))
		if err != nil {
			t.Fatalf("published file %s is missing: %v", relative, err)
		}
		if info.Mode().Perm()&0o222 != 0 {
			t.Fatalf("published file %s is writable", relative)
		}
	}
	if err := filepath.WalkDir(destination, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return os.Chmod(path, 0o700)
		}
		return os.Chmod(path, 0o600)
	}); err != nil {
		t.Fatal(err)
	}
}

func TestWorkspaceRejectsNonUTF8Source(t *testing.T) {
	workspace, err := NewWorkspace(filepath.Join(t.TempDir(), "work"), "run-2", 1024)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = workspace.Cleanup() })
	if err := workspace.WriteFile("bad.py", "python", strings.NewReader(string([]byte{0xff, 0xfe}))); err == nil {
		t.Fatal("expected invalid UTF-8 source to be rejected")
	}
}

func TestBlobStoreHashesOnlyAtIngestAndReusesContentIdentity(t *testing.T) {
	store, err := NewBlobStore(filepath.Join(t.TempDir(), "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.Ingest(strings.NewReader("same input"), 1024)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Ingest(strings.NewReader("same input"), 1024)
	if err != nil {
		t.Fatal(err)
	}
	if first.StorageKey != second.StorageKey || first.SHA256 != second.SHA256 {
		t.Fatal("identical input did not reuse the same content identity")
	}
}
