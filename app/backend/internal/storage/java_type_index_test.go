package storage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestJavaTypeIndexPinsOriginalInputAndStaysOutsideSourceFiles(t *testing.T) {
	root := t.TempDir()
	w, err := NewWorkspace(filepath.Join(root, "work"), "run", 4096)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Cleanup() })
	if err = w.WriteFile("Probe.java", "java", strings.NewReader("class Probe {}")); err != nil {
		t.Fatal(err)
	}
	body := `{"version":"java-type-index-v1","inputSha256":"` + strings.Repeat("a", 64) + `","types":[]}`
	if err = w.WriteJavaTypeIndex(strings.NewReader(body)); err != nil {
		t.Fatal(err)
	}
	if _, err = w.PublishProject(filepath.Join(root, "projects"), "wrong", Manifest{RunID: "run", Kind: "jvm", Language: "java", InputSHA256: strings.Repeat("b", 64)}); err == nil {
		t.Fatal("mismatched original input accepted")
	}
	p, err := w.PublishProject(filepath.Join(root, "projects"), "correct", Manifest{RunID: "run", Kind: "jvm", Language: "java", InputSHA256: strings.Repeat("a", 64)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(p.Root, 0700)
		_ = os.Chmod(filepath.Join(p.Root, ".binaryscan"), 0700)
		_ = os.Chmod(filepath.Join(p.Root, ".binaryscan/java-types.json"), 0600)
	})
	if len(p.Manifest.Files) != 1 || p.Manifest.JavaTypeIndex == nil {
		t.Fatal("metadata polluted source files")
	}
	data, err := ReadJavaTypeIndex(p.Root, p.Manifest)
	if err != nil || string(data) != body {
		t.Fatalf("sidecar unreadable: %v", err)
	}
	p.Manifest.JavaTypeIndex.SHA256 = strings.Repeat("0", 64)
	if _, err = ReadJavaTypeIndex(p.Root, p.Manifest); err == nil {
		t.Fatal("digest change accepted")
	}
	p.Manifest.JavaTypeIndex.Path = "../java-types.json"
	if _, err = ReadJavaTypeIndex(p.Root, p.Manifest); err == nil {
		t.Fatal("escaping sidecar accepted")
	}
}
