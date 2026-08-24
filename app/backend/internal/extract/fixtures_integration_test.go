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
// that every advertised archive yields the expected binary-task candidates.
func TestFixtureArchiveEligibility(t *testing.T) {
	root := os.Getenv("BINARY_FIXTURE_ROOT")
	if root == "" {
		t.Skip("BINARY_FIXTURE_ROOT is not set")
	}
	pairExpected := map[string]string{
		"vulnerable-elf": "elf64",
		"vulnerable.exe": "pe32+",
	}
	isoExpected := map[string]string{
		"VULNERABLE-ELF": "elf64",
		"VULNERABLE.EXE": "pe32+",
	}
	tests := []struct {
		name     string
		format   string
		expected map[string]string
	}{
		{name: "vulnerable-binaries.zip", format: "zip", expected: pairExpected},
		{name: "vulnerable-binaries.7z", format: "7z", expected: pairExpected},
		{name: "vulnerable-binaries.rar", format: "rar", expected: pairExpected},
		{name: "vulnerable-binaries.tar", format: "tar", expected: pairExpected},
		{name: "vulnerable-elf.gz", format: "gzip", expected: map[string]string{"vulnerable-elf": "elf64"}},
		{name: "vulnerable-elf.xz", format: "xz", expected: map[string]string{"vulnerable-elf": "elf64"}},
		{name: "vulnerable-binaries.deb", format: "deb", expected: map[string]string{"vulnerable-elf": "elf64"}},
		{name: "vulnerable-binaries.rpm", format: "rpm", expected: map[string]string{"vulnerable-elf": "elf64"}},
		{name: "vulnerable-binaries.iso", format: "iso9660", expected: isoExpected},
		{name: "vulnerable-binaries.ext4", format: "ext4", expected: pairExpected},
		{name: "vulnerable-binaries.jar", format: "zip", expected: map[string]string{"VulnerableFixture$Cookie.class": "java-class", "VulnerableFixture.class": "java-class"}},
		{name: "vulnerable-binaries.apk", format: "zip", expected: map[string]string{"classes.dex": "dex"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := make(map[string]string)
			filename := filepath.Join(root, "02-archive", test.name)
			err := Walk(context.Background(), filename, filepath.Base(filename), test.format, 100,
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
						return nil
					}
					actual[logicalPath] = detected.Format
					return nil
				})
			if err != nil {
				t.Fatal(err)
			}
			if len(actual) != len(test.expected) {
				t.Fatalf("eligible members = %v, want %v", actual, test.expected)
			}
			for path, expectedFormat := range test.expected {
				if actual[path] != expectedFormat {
					t.Errorf("%s format = %q, want %q", path, actual[path], expectedFormat)
				}
			}
		})
	}
}
