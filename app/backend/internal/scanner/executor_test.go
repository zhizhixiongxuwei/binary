package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectFileRoutesRepresentativeFormats(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		header   []byte
		expected string
	}{
		{name: "elf", filename: "sample", header: []byte{0x7f, 'E', 'L', 'F'}, expected: "elf"},
		{name: "java class before fat Mach-O", filename: "Sample.class", header: []byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 61}, expected: "class"},
		{name: "Mach-O", filename: "sample", header: []byte{0xcf, 0xfa, 0xed, 0xfe}, expected: "mach-o"},
		{name: "APK", filename: "sample.apk", header: []byte{'P', 'K', 3, 4}, expected: "apk"},
		{name: "PYC", filename: "sample.pyc", header: []byte{0xcb, 0x0d, 0x0d, 0x0a}, expected: "pyc"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "input")
			if err := os.WriteFile(path, test.header, 0o600); err != nil {
				t.Fatal(err)
			}
			actual, err := detectFile(path, test.filename)
			if err != nil {
				t.Fatal(err)
			}
			if actual != test.expected {
				t.Fatalf("detectFile() = %q, want %q", actual, test.expected)
			}
		})
	}
}
