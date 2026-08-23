package extract

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/ulikunitz/xz"
)

func TestWalkCommonArchives(t *testing.T) {
	t.Run("ZIP", func(t *testing.T) {
		filename := filepath.Join(t.TempDir(), "sample.zip")
		file, err := os.Create(filename)
		if err != nil {
			t.Fatal(err)
		}
		writer := zip.NewWriter(file)
		entry, _ := writer.Create("bin/demo")
		_, _ = entry.Write([]byte("zip-data"))
		_ = writer.Close()
		_ = file.Close()
		assertWalk(t, filename, "sample.zip", "zip", "bin/demo", "zip-data")
	})

	t.Run("tar.gz logical layer", func(t *testing.T) {
		filename := filepath.Join(t.TempDir(), "sample.tar.gz")
		file, err := os.Create(filename)
		if err != nil {
			t.Fatal(err)
		}
		gz := gzip.NewWriter(file)
		tarWriter := tar.NewWriter(gz)
		body := []byte("gzip-tar-data")
		_ = tarWriter.WriteHeader(&tar.Header{Name: "app/demo", Mode: 0o600, Size: int64(len(body))})
		_, _ = tarWriter.Write(body)
		_ = tarWriter.Close()
		_ = gz.Close()
		_ = file.Close()
		assertWalk(t, filename, "sample.tar.gz", "gzip", "app/demo", string(body))
	})

	t.Run("XZ stream", func(t *testing.T) {
		filename := filepath.Join(t.TempDir(), "sample.bin.xz")
		file, err := os.Create(filename)
		if err != nil {
			t.Fatal(err)
		}
		writer, err := xz.NewWriter(file)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = writer.Write([]byte("xz-data"))
		_ = writer.Close()
		_ = file.Close()
		assertWalk(t, filename, "sample.bin.xz", "xz", "sample.bin", "xz-data")
	})

	t.Run("DEB expands data payload only", func(t *testing.T) {
		filename := filepath.Join(t.TempDir(), "sample.deb")
		dataPayload := tarGZIPBody(t, "usr/bin/demo", "deb-binary")
		var deb bytes.Buffer
		deb.WriteString("!<arch>\n")
		writeARMember(t, &deb, "debian-binary", []byte("2.0\n"))
		writeARMember(t, &deb, "control.tar.gz", tarGZIPBody(t, "control", "Package: demo\n"))
		writeARMember(t, &deb, "data.tar.gz", dataPayload)
		if err := os.WriteFile(filename, deb.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
		assertWalk(t, filename, "sample.deb", "deb", "usr/bin/demo", "deb-binary")
	})
}

func assertWalk(t *testing.T, filename, sourceName, format, expectedName, expectedBody string) {
	t.Helper()
	var names []string
	var bodies [][]byte
	err := Walk(context.Background(), filename, sourceName, format, 10, func(entry Entry, reader io.Reader) error {
		names = append(names, entry.Name)
		body, err := io.ReadAll(reader)
		bodies = append(bodies, body)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[0] != expectedName || !bytes.Equal(bodies[0], []byte(expectedBody)) {
		t.Fatalf("Walk() = names=%v bodies=%q", names, bodies)
	}
}

func tarGZIPBody(t *testing.T, name, content string) []byte {
	t.Helper()
	var output bytes.Buffer
	gz := gzip.NewWriter(&output)
	writer := tar.NewWriter(gz)
	body := []byte(content)
	if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func writeARMember(t *testing.T, output *bytes.Buffer, name string, body []byte) {
	t.Helper()
	header := fmt.Sprintf("%-16s%-12d%-6d%-6d%-8o%-10d`\n", name+"/", 0, 0, 0, 0o100644, len(body))
	if len(header) != 60 {
		t.Fatalf("ar header length = %d", len(header))
	}
	output.WriteString(header)
	output.Write(body)
	if len(body)%2 != 0 {
		output.WriteByte('\n')
	}
}
