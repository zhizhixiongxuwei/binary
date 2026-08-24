package extract

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"binaryscan.local/backend/internal/filetype"
)

// This optional fixture test complements TestFixtureArchiveCorpus by proving
// that every member is binary-task eligible and has the expected format.
func TestFixtureArchiveEligibility(t *testing.T) {
	root := os.Getenv("BINARY_FIXTURE_ROOT")
	if root == "" {
		t.Skip("BINARY_FIXTURE_ROOT is not set")
	}
	expected := map[string]string{
		"VulnerableFixture.class": "java-class",
		"vulnerable-macho":        "macho-thin",
		"vulnerable.jar":          "jar",
		"vulnerable.pyc":          "pyc",
	}
	actual := make(map[string]string)
	filename := filepath.Join(root, "02-archive", "vulnerable-binaries.zip")
	err := Walk(context.Background(), filename, filepath.Base(filename), "zip", 100,
		func(entry Entry, reader io.Reader) error {
			if !entry.Regular || entry.Size == 0 {
				return nil
			}
			logicalPath := filepath.Base(entry.Name)
			temporary, err := os.CreateTemp(t.TempDir(), "archive-entry-*")
			if err != nil {
				return err
			}
			name := temporary.Name()
			defer os.Remove(name)
			if _, err := io.Copy(temporary, reader); err != nil {
				_ = temporary.Close()
				return err
			}
			if err := temporary.Close(); err != nil {
				return err
			}
			detected, err := filetype.Detect(name, logicalPath)
			if err != nil {
				return err
			}
			if detected.Category != filetype.CategoryBinary {
				t.Fatalf("%s category = %q, want %q", logicalPath, detected.Category, filetype.CategoryBinary)
			}
			actual[logicalPath] = detected.Format
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if len(actual) != len(expected) {
		t.Fatalf("eligible members = %v, want %v", actual, expected)
	}
	for path, expectedFormat := range expected {
		if actual[path] != expectedFormat {
			t.Errorf("%s format = %q, want %q", path, actual[path], expectedFormat)
		}
	}
}
