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
// that only the three expected members are binary-task eligible.
func TestFixtureArchiveEligibility(t *testing.T) {
	root := os.Getenv("BINARY_FIXTURE_ROOT")
	if root == "" {
		t.Skip("BINARY_FIXTURE_ROOT is not set")
	}
	tests := []struct {
		name   string
		format string
	}{
		{"sample.zip", "zip"},
		{"sample.7z", "7z"},
		{"sample.rar", "rar"},
		{"sample.tar", "tar"},
		{"sample.tar.gz", "gzip"},
		{"sample.tar.xz", "xz"},
		{"sample.deb", "deb"},
		{"sample.rpm", "rpm"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			filename := filepath.Join(root, "02-archive", test.name)
			binaryFormats := make(map[string]int)
			nestedArchives, regularEntries := 0, 0
			err := Walk(context.Background(), filename, test.name, test.format, 100,
				func(entry Entry, reader io.Reader) error {
					if !entry.Regular || entry.Size == 0 {
						return nil
					}
					regularEntries++
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
					detected, err := filetype.Detect(name, filepath.Base(entry.Name))
					if err != nil {
						return err
					}
					switch detected.Category {
					case filetype.CategoryBinary:
						binaryFormats[detected.Format]++
					case filetype.CategoryArchive:
						nestedArchives++
					}
					return nil
				})
			if err != nil {
				t.Fatal(err)
			}
			if regularEntries != 5 || nestedArchives != 1 ||
				binaryFormats["elf64"] != 1 || binaryFormats["java-class"] != 1 || binaryFormats["pyc"] != 1 ||
				len(binaryFormats) != 3 {
				t.Fatalf("entries=%d nested=%d binaries=%v", regularEntries, nestedArchives, binaryFormats)
			}
		})
	}
}
