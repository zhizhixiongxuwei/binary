package filetype

import (
	"os"
	"path/filepath"
	"testing"
)

// TestFixtureCorpus is optional in normal CI. Set BINARY_FIXTURE_ROOT to the
// generated binary-repo directory to exercise the detector against every
// decompiler/checker regression binary, archive/filesystem bundle, and
// container image fixtures.
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
		{"01-binary/vulnerable.exe", "pe32+", CategoryBinary},
		{"01-binary/vulnerable.dll", "pe32+", CategoryBinary},
		{"01-binary/vulnerable.sys", "pe32+", CategoryBinary},
		{"01-binary/vulnerable-elf", "elf64", CategoryBinary},
		{"01-binary/vulnerable-macho", "macho-thin", CategoryBinary},
		{"01-binary/VulnerableFixture.class", "java-class", CategoryBinary},
		{"01-binary/vulnerable.jar", "jar", CategoryBinary},
		{"01-binary/vulnerable.dex", "dex", CategoryBinary},
		{"01-binary/vulnerable.apk", "apk", CategoryBinary},
		{"01-binary/vulnerable.pyc", "pyc", CategoryBinary},
		{"02-archive/vulnerable-binaries.zip", "zip", CategoryArchive},
		{"02-archive/vulnerable-binaries.7z", "7z", CategoryArchive},
		{"02-archive/vulnerable-binaries.rar", "rar", CategoryArchive},
		{"02-archive/vulnerable-binaries.tar", "tar", CategoryArchive},
		{"02-archive/vulnerable-elf.gz", "gzip", CategoryArchive},
		{"02-archive/vulnerable-elf.xz", "xz", CategoryArchive},
		{"02-archive/vulnerable-binaries.deb", "deb", CategoryArchive},
		{"02-archive/vulnerable-binaries.rpm", "rpm", CategoryArchive},
		{"02-archive/vulnerable-binaries.iso", "iso9660", CategoryArchive},
		{"02-archive/vulnerable-binaries.ext4", "ext4", CategoryContainer},
		{"02-archive/vulnerable-binaries.jar", "jar", CategoryBinary},
		{"02-archive/vulnerable-binaries.apk", "apk", CategoryBinary},
		{"03-container/docker-save.tar", "docker-tar", CategoryContainer},
		{"03-container/docker-save.img", "docker-tar", CategoryContainer},
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
