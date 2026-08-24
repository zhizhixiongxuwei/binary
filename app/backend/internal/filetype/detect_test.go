package filetype

import (
	"archive/tar"
	"archive/zip"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDetectCanonicalFormats(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		body     []byte
		format   string
		category Category
	}{
		{name: "ELF64", filename: "demo", body: []byte{0x7f, 'E', 'L', 'F', 2}, format: "elf64", category: CategoryBinary},
		{name: "class", filename: "Demo.class", body: []byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 61}, format: "java-class", category: CategoryBinary},
		{name: "Mach-O", filename: "demo", body: []byte{0xcf, 0xfa, 0xed, 0xfe}, format: "macho-thin", category: CategoryBinary},
		{name: "DEX", filename: "classes.dex", body: []byte("dex\n035\x00"), format: "dex", category: CategoryBinary},
		{name: "PYC", filename: "demo.pyc", body: append([]byte{0xcb, 0x0d, '\r', '\n'}, make([]byte, 12)...), format: "pyc", category: CategoryBinary},
		{name: "7Z", filename: "demo.7z", body: []byte{0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c}, format: "7z", category: CategoryArchive},
		{name: "RAR5", filename: "demo.rar", body: []byte("Rar!\x1a\x07\x01\x00"), format: "rar", category: CategoryArchive},
		{name: "GZIP", filename: "demo.gz", body: []byte{0x1f, 0x8b}, format: "gzip", category: CategoryArchive},
		{name: "XZ", filename: "demo.xz", body: []byte{0xfd, '7', 'z', 'X', 'Z', 0}, format: "xz", category: CategoryArchive},
		{name: "RPM", filename: "demo.rpm", body: []byte{0xed, 0xab, 0xee, 0xdb}, format: "rpm", category: CategoryArchive},
		{name: "ISO 9660", filename: "demo.img", body: iso9660Body(), format: "iso9660", category: CategoryArchive},
		{name: "EXT4 image", filename: "rootfs.ext4", body: ext4Body(), format: "ext4", category: CategoryContainer},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "input")
			if err := os.WriteFile(path, test.body, 0o600); err != nil {
				t.Fatal(err)
			}
			actual, err := Detect(path, test.filename)
			if err != nil {
				t.Fatal(err)
			}
			if actual.Format != test.format || actual.Category != test.category {
				t.Fatalf("Detect() = %#v, want %s/%s", actual, test.category, test.format)
			}
		})
	}
}

func ext4Body() []byte {
	body := make([]byte, 2*1024)
	binary.LittleEndian.PutUint16(body[1024+0x38:], 0xef53)
	return body
}

func iso9660Body() []byte {
	body := make([]byte, 40*1024)
	offset := 16 * 2048
	body[offset] = 1
	copy(body[offset+1:], "CD001")
	body[offset+6] = 1
	return body
}

func TestDetectPEAndZipApplications(t *testing.T) {
	t.Run("PE signature", func(t *testing.T) {
		body := make([]byte, 256)
		copy(body, "MZ")
		binary.LittleEndian.PutUint32(body[0x3c:0x40], 0x80)
		copy(body[0x80:], []byte{'P', 'E', 0, 0})
		assertDetected(t, "demo.exe", body, "pe32", CategoryBinary)
	})
	t.Run("JAR contents", func(t *testing.T) {
		assertDetected(t, "renamed.bin", zipBody(t, map[string]string{"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\n"}), "jar", CategoryBinary)
	})
	t.Run("APK contents", func(t *testing.T) {
		assertDetected(t, "renamed.bin", zipBody(t, map[string]string{"AndroidManifest.xml": "manifest", "classes.dex": "dex\n035\x00"}), "apk", CategoryBinary)
	})
	t.Run("ordinary ZIP", func(t *testing.T) {
		assertDetected(t, "demo.zip", zipBody(t, map[string]string{"Fixture.class": "class candidate"}), "zip", CategoryArchive)
	})
	t.Run("JAR extension with classes", func(t *testing.T) {
		assertDetected(t, "demo.jar", zipBody(t, map[string]string{"Fixture.class": "class candidate"}), "jar", CategoryBinary)
	})
}

func TestDetectContainerTAR(t *testing.T) {
	body := tarBody(t, map[string]string{
		"manifest.json": `[{"Config":"config.json","Layers":["layer.tar"]}]`,
		"config.json":   `{}`,
		"layer.tar":     "layer",
	})
	assertDetected(t, "image.img", body, "docker-tar", CategoryContainer)
}

func TestAnalysisModeCapabilities(t *testing.T) {
	t.Parallel()
	tests := []struct {
		format string
		mode   AnalysisMode
		want   bool
	}{
		{format: "pe32", mode: AnalysisModeBinary, want: true},
		{format: "jar", mode: AnalysisModeArchive, want: true},
		{format: "apk", mode: AnalysisModeArchive, want: true},
		{format: "iso9660", mode: AnalysisModeArchive, want: true},
		{format: "iso9660", mode: AnalysisModeContainer, want: false},
		{format: "ext4", mode: AnalysisModeContainer, want: false},
		{format: "docker-tar", mode: AnalysisModeArchive, want: true},
		{format: "docker-tar", mode: AnalysisModeContainer, want: true},
		{format: "oci-tar", mode: AnalysisModeContainer, want: true},
	}
	for _, test := range tests {
		if actual := SupportsAnalysisMode(test.format, test.mode); actual != test.want {
			t.Errorf("SupportsAnalysisMode(%q, %q) = %v, want %v", test.format, test.mode, actual, test.want)
		}
	}

	for format, want := range map[string]string{
		"jar": "zip", "apk": "zip", "docker-tar": "tar", "oci-tar": "tar", "iso9660": "iso9660",
	} {
		actual, ok := ArchiveFormat(format)
		if !ok || actual != want {
			t.Errorf("ArchiveFormat(%q) = %q, %v, want %q, true", format, actual, ok, want)
		}
	}
}

func TestDetectClassifiesMalformedInputSeparatelyFromStorageFailure(t *testing.T) {
	t.Parallel()

	malformed := filepath.Join(t.TempDir(), "malformed.zip")
	if err := os.WriteFile(malformed, []byte{'P', 'K', 3, 4, 0}, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Detect(malformed, "malformed.zip"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("malformed ZIP error = %v, want ErrInvalidInput", err)
	}

	if _, err := Detect(filepath.Join(t.TempDir(), "missing"), "missing.zip"); err == nil || errors.Is(err, ErrInvalidInput) {
		t.Fatalf("missing-file error = %v, want operational error", err)
	}
}

func assertDetected(t *testing.T, name string, body []byte, format string, category Category) {
	t.Helper()
	filename := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(filename, body, 0o600); err != nil {
		t.Fatal(err)
	}
	actual, err := Detect(filename, name)
	if err != nil {
		t.Fatal(err)
	}
	if actual.Format != format || actual.Category != category {
		t.Fatalf("Detect() = %#v, want %s/%s", actual, category, format)
	}
}

func zipBody(t *testing.T, members map[string]string) []byte {
	t.Helper()
	filename := filepath.Join(t.TempDir(), "sample.zip")
	file, err := os.Create(filename)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(file)
	for name, body := range members {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func tarBody(t *testing.T, members map[string]string) []byte {
	t.Helper()
	filename := filepath.Join(t.TempDir(), "sample.tar")
	file, err := os.Create(filename)
	if err != nil {
		t.Fatal(err)
	}
	writer := tar.NewWriter(file)
	for name, body := range members {
		if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	return body
}
