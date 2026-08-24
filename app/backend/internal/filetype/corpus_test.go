package filetype

import (
	"os"
	"path/filepath"
	"testing"
)

// TestFixtureCorpus is optional in normal CI. Set BINARY_FIXTURE_ROOT to the
// generated binary-repo directory to exercise the detector against the four
// decompiler/checker regression binaries and their one-layer ZIP bundle.
func TestFixtureCorpus(t *testing.T) {
	root := os.Getenv("BINARY_FIXTURE_ROOT")
	if root == "" {
		t.Skip("BINARY_FIXTURE_ROOT is not set")
	}
	tests := []struct {
		path     string
		format   string
		category Category
	}{
		{"01-binary/vulnerable-macho", "macho-thin", CategoryBinary},
		{"01-binary/VulnerableFixture.class", "java-class", CategoryBinary},
		{"01-binary/vulnerable.jar", "jar", CategoryBinary},
		{"01-binary/vulnerable.pyc", "pyc", CategoryBinary},
		{"02-archive/vulnerable-binaries.zip", "zip", CategoryArchive},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			filename := filepath.Join(root, filepath.FromSlash(test.path))
			actual, err := Detect(filename, filepath.Base(filename))
			if err != nil {
				t.Fatal(err)
			}
			if actual.Format != test.format || actual.Category != test.category {
				t.Fatalf("Detect() = %#v, want %s/%s", actual, test.category, test.format)
			}
		})
	}
}
