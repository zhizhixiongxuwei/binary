package containerarchive

import (
	"archive/tar"
	"os"
	"path/filepath"
	"testing"
)

func TestInspectTAR(t *testing.T) {
	tests := []struct {
		name     string
		members  map[string]string
		expected string
		ok       bool
	}{
		{name: "docker save", members: map[string]string{
			"manifest.json":   `[{"Config":"config.json","RepoTags":["demo:latest"],"Layers":["layer/layer.tar"]}]`,
			"config.json":     `{}`,
			"layer/layer.tar": "layer",
		}, expected: FormatDockerTAR, ok: true},
		{name: "OCI layout", members: map[string]string{
			"oci-layout": `{"imageLayoutVersion":"1.0.0"}`,
			"index.json": `{"schemaVersion":2,"manifests":[]}`,
			"blobs/sha256/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": `{}`,
		}, expected: FormatOCITAR, ok: true},
		{name: "ordinary tar", members: map[string]string{"sample.bin": "data"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			filename := filepath.Join(t.TempDir(), "sample.tar")
			writeTar(t, filename, test.members)
			format, ok, err := InspectTAR(filename)
			if err != nil {
				t.Fatal(err)
			}
			if format != test.expected || ok != test.ok {
				t.Fatalf("InspectTAR() = (%q, %v), want (%q, %v)", format, ok, test.expected, test.ok)
			}
		})
	}
}

func writeTar(t *testing.T, filename string, members map[string]string) {
	t.Helper()
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
}
