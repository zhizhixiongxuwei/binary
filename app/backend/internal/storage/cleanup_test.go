package storage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRemoveTreeHandlesReadOnlyProjectsAndSymlinks(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	protected := filepath.Join(outside, "keep.txt")
	if err := os.WriteFile(protected, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(root, "projects", "jvm", "project", "src")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "Main.java"), []byte("class Main {}"), 0o440); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(project, "external")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(project, 0o550); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(project), 0o550); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := RemoveTree(root, "projects/jvm/project"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(protected); err != nil {
		t.Fatalf("external file changed: %v", err)
	}
	if err := RemoveTree(root, "../outside"); err == nil {
		t.Fatal("accepted an escaping path")
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := RemoveTree(root, "escape/keep.txt"); err == nil {
		t.Fatal("followed a parent symlink outside storage")
	}
	if _, err := os.Stat(protected); err != nil {
		t.Fatal(err)
	}
}

func TestPublicationLockProtectsInFlightIngestion(t *testing.T) {
	store, err := NewBlobStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	release, err := store.LockPublication(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := store.LockPublication(ctx, true); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cleanup did not wait for ingestion: %v", err)
	}
	release()
	release, err = store.LockPublication(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	release()
}
