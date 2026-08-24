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

// TestFixtureArchiveCorpus verifies every advertised one-layer reader against
// a real fixture. Eligibility is checked separately below the extraction layer.
func TestFixtureArchiveCorpus(t *testing.T) {
	root := os.Getenv("BINARY_FIXTURE_ROOT")
	if root == "" {
		t.Skip("BINARY_FIXTURE_ROOT is not set")
	}
	pairExpected := []string{"vulnerable-elf", "vulnerable.exe"}
	isoExpected := []string{
		"VULNERABLE-ELF",
		"VULNERABLE.EXE",
	}
	tests := []struct {
		name     string
		format   string
		expected []string
	}{
		{name: "vulnerable-binaries.zip", format: "zip", expected: pairExpected},
		{name: "vulnerable-binaries.7z", format: "7z", expected: pairExpected},
		{name: "vulnerable-binaries.rar", format: "rar", expected: pairExpected},
		{name: "vulnerable-binaries.tar", format: "tar", expected: pairExpected},
		{name: "vulnerable-elf.gz", format: "gzip", expected: []string{"vulnerable-elf"}},
		{name: "vulnerable-elf.xz", format: "xz", expected: []string{"vulnerable-elf"}},
		{name: "vulnerable-binaries.deb", format: "deb", expected: []string{"usr/bin/vulnerable-elf"}},
		{name: "vulnerable-binaries.rpm", format: "rpm", expected: []string{"usr/bin/vulnerable-elf"}},
		{name: "vulnerable-binaries.iso", format: "iso9660", expected: isoExpected},
		{name: "vulnerable-binaries.ext4", format: "ext4", expected: pairExpected},
		{name: "vulnerable-binaries.jar", format: "zip", expected: []string{"META-INF/MANIFEST.MF", "VulnerableFixture$Cookie.class", "VulnerableFixture.class"}},
		{name: "vulnerable-binaries.apk", format: "zip", expected: []string{"AndroidManifest.xml", "classes.dex"}},
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
