package storage

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"binaryscan.local/backend/internal/jvmarchive"
)

const JavaTypeIndexLimit = 24 << 20

func (w *Workspace) WriteJavaTypeIndex(source io.Reader) error {
	body, err := io.ReadAll(io.LimitReader(source, JavaTypeIndexLimit+1))
	if err != nil || len(body) > JavaTypeIndexLimit {
		return fmt.Errorf("Java type sidecar exceeds limit")
	}
	var header struct{ Version, InputSHA256 string }
	if json.Unmarshal(body, &header) != nil || header.Version != "java-type-index-v1" || len(header.InputSHA256) != 64 {
		return fmt.Errorf("invalid Java type sidecar")
	}
	destination := filepath.Join(w.root, filepath.FromSlash(jvmarchive.TypeIndexPath))
	if err := os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
		return err
	}
	if err := os.WriteFile(destination, body, 0600); err != nil {
		return err
	}
	w.javaTypeIndex = &ManifestSidecar{Path: jvmarchive.TypeIndexPath, SHA256: fmt.Sprintf("%x", sha256.Sum256(body)), SizeBytes: int64(len(body))}
	w.javaTypeInputSHA = header.InputSHA256
	return nil
}
func ReadJavaTypeIndex(root string, manifest Manifest) ([]byte, error) {
	meta := manifest.JavaTypeIndex
	if meta == nil {
		return nil, nil
	}
	if manifest.Kind != "jvm" || meta.Path != jvmarchive.TypeIndexPath || meta.SizeBytes < 1 || meta.SizeBytes > JavaTypeIndexLimit {
		return nil, fmt.Errorf("invalid Java type sidecar identity")
	}
	file := filepath.Join(root, filepath.FromSlash(meta.Path))
	info, err := os.Lstat(file)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() != meta.SizeBytes {
		return nil, fmt.Errorf("Java type sidecar is not the pinned regular file")
	}
	stream, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	body, err := io.ReadAll(io.LimitReader(stream, meta.SizeBytes+1))
	if err != nil || int64(len(body)) != meta.SizeBytes || fmt.Sprintf("%x", sha256.Sum256(body)) != meta.SHA256 {
		return nil, fmt.Errorf("Java type sidecar digest mismatch")
	}
	var header struct{ Version, InputSHA256 string }
	if json.Unmarshal(body, &header) != nil || header.Version != "java-type-index-v1" || header.InputSHA256 != manifest.InputSHA256 {
		return nil, fmt.Errorf("Java type sidecar original input mismatch")
	}
	return body, nil
}
