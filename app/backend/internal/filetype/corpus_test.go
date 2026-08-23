package filetype

import (
	"os"
	"path/filepath"
	"testing"
)

// TestFixtureCorpus is optional in normal CI. Set BINARY_FIXTURE_ROOT to the
// generated binary-repo directory to exercise the detector against all 18
// reproducible upload fixtures, rather than only minimal in-memory headers.
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
		{"01-binary/sample-pe.exe", "pe32+", CategoryBinary},
		{"01-binary/sample-elf", "elf64", CategoryBinary},
		{"01-binary/sample-macho", "macho-thin", CategoryBinary},
		{"01-binary/Fixture.class", "java-class", CategoryBinary},
		{"01-binary/sample.jar", "jar", CategoryBinary},
		{"01-binary/sample.dex", "dex", CategoryBinary},
		{"01-binary/sample.apk", "apk", CategoryBinary},
		{"01-binary/sample.pyc", "pyc", CategoryBinary},
		{"02-archive/sample.zip", "zip", CategoryArchive},
		{"02-archive/sample.7z", "7z", CategoryArchive},
		{"02-archive/sample.rar", "rar", CategoryArchive},
		{"02-archive/sample.tar", "tar", CategoryArchive},
		{"02-archive/sample.tar.gz", "gzip", CategoryArchive},
		{"02-archive/sample.tar.xz", "xz", CategoryArchive},
		{"02-archive/sample.deb", "deb", CategoryArchive},
		{"02-archive/sample.rpm", "rpm", CategoryArchive},
		{"03-container/docker-save.tar", "docker-tar", CategoryContainer},
		{"03-container/oci-layout.tar", "oci-tar", CategoryContainer},
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
