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

// TestFixtureArchiveCorpus verifies that ZIP and ISO 9660 variants expose
// exactly the four binaries whose decompiled source produces checker findings.
func TestFixtureArchiveCorpus(t *testing.T) {
	root := os.Getenv("BINARY_FIXTURE_ROOT")
	if root == "" {
		t.Skip("BINARY_FIXTURE_ROOT is not set")
	}
	zipExpected := []string{
		"VulnerableFixture.class",
		"vulnerable-macho",
		"vulnerable.jar",
		"vulnerable.pyc",
	}
	isoExpected := []string{
		"VULNERABLE-MACHO",
		"VULNERABLE.JAR",
		"VULNERABLE.PYC",
		"VULNERABLEFIXTURE.CLASS",
	}
	tests := []struct {
		name     string
		format   string
		expected []string
	}{
		{name: "vulnerable-binaries.zip", format: "zip", expected: zipExpected},
		{name: "vulnerable-binaries.iso", format: "iso9660", expected: isoExpected},
		{name: "vulnerable-binaries.img", format: "iso9660", expected: isoExpected},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			filename := filepath.Join(root, "02-archive", test.name)
			var names []string
			err := Walk(context.Background(), filename, filepath.Base(filename), test.format, 100,
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
			sort.Strings(names)
			sort.Strings(test.expected)
			if strings.Join(names, "\n") != strings.Join(test.expected, "\n") {
				t.Fatalf("one-layer entries = %q, want %q", names, test.expected)
			}
		})
	}
}
