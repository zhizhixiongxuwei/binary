package storage

import (
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
	destination, err := workspace.Publish(filepath.Join(root, "projects"), "project-1", Manifest{
		RunID: "run-1", Kind: "native", Language: "c", Quality: "source", ToolName: "test", ToolVersion: "1",
	})
	if err != nil {
		t.Fatal(err)
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
