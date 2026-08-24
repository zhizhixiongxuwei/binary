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

// TestFixtureArchiveCorpus verifies the externally generated upload corpus
// when BINARY_FIXTURE_ROOT is provided. Each format must expose exactly one
// logical payload layer; nested.zip remains an opaque entry.
func TestFixtureArchiveCorpus(t *testing.T) {
	root := os.Getenv("BINARY_FIXTURE_ROOT")
	if root == "" {
		t.Skip("BINARY_FIXTURE_ROOT is not set")
	}
	tests := []struct {
		name   string
		format string
		prefix string
	}{
		{"sample.zip", "zip", ""},
		{"sample.7z", "7z", ""},
		{"sample.rar", "rar", ""},
		{"sample.tar", "tar", ""},
		{"sample.tar.gz", "gzip", ""},
		{"sample.tar.xz", "xz", ""},
		{"sample.deb", "deb", "usr/share/binaryscan-fixture/"},
		{"sample.rpm", "rpm", "usr/share/binaryscan-fixture/"},
	}
	expectedBase := []string{"README.txt", "SafeZeroFindingsFixture.class", "nested.zip", "safe-zero-findings-elf", "safe-zero-findings.pyc"}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var names []string
			filename := filepath.Join(root, "02-archive", test.name)
			err := Walk(context.Background(), filename, test.name, test.format, 100,
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
			expected := make([]string, len(expectedBase))
			for index, name := range expectedBase {
				expected[index] = test.prefix + name
			}
			sort.Strings(names)
			sort.Strings(expected)
			if strings.Join(names, "\n") != strings.Join(expected, "\n") {
				t.Fatalf("one-layer entries = %q, want %q", names, expected)
			}
			for _, name := range names {
				if strings.Contains(name, "nested-note") {
					t.Fatalf("nested archive was expanded recursively: %q", name)
				}
			}
		})
	}
}
