package extract

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestFixtureArchiveCorpus verifies that the regression ZIP exposes exactly
// the four binaries whose decompiled source produces checker findings.
func TestFixtureArchiveCorpus(t *testing.T) {
	root := os.Getenv("BINARY_FIXTURE_ROOT")
	if root == "" {
		t.Skip("BINARY_FIXTURE_ROOT is not set")
	}
	filename := filepath.Join(root, "02-archive", "vulnerable-binaries.zip")
	var names []string
	err := Walk(context.Background(), filename, filepath.Base(filename), "zip", 100,
		func(entry Entry, reader io.Reader) error {
			if !entry.Regular {
				return nil
			}
			names = append(names, strings.TrimPrefix(entry.Name, "./"))
			_, err := io.Copy(io.Discard, reader)
			return err
		})
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{
		"VulnerableFixture.class",
		"vulnerable-macho",
		"vulnerable.jar",
		"vulnerable.pyc",
	}
	sort.Strings(names)
	sort.Strings(expected)
	if strings.Join(names, "\n") != strings.Join(expected, "\n") {
		t.Fatalf("one-layer entries = %q, want %q", names, expected)
	}
}
