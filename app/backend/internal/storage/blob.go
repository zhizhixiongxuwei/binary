package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

var ErrBlobTooLarge = errors.New("blob exceeds the configured byte limit")

type Blob struct {
	SHA256     [32]byte
	SizeBytes  int64
	StorageKey string
}

type BlobStore struct {
	root string
}

func NewBlobStore(root string) (*BlobStore, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve blob root: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(absRoot, ".staging"), 0o700); err != nil {
		return nil, fmt.Errorf("create blob staging directory: %w", err)
	}
	return &BlobStore{root: absRoot}, nil
}

// Ingest computes the only application-level content digest: once, while a new
// blob crosses from an upload or archive stream into immutable storage.
func (s *BlobStore) Ingest(source io.Reader, maxBytes int64) (Blob, error) {
	if maxBytes <= 0 {
		return Blob{}, fmt.Errorf("blob byte limit must be positive")
	}
	temporary, err := os.CreateTemp(filepath.Join(s.root, ".staging"), "blob-*")
	if err != nil {
		return Blob{}, fmt.Errorf("create blob staging file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)

	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(temporary, hash), io.LimitReader(source, maxBytes+1))
	closeErr := temporary.Close()
	if copyErr != nil {
		return Blob{}, fmt.Errorf("write blob: %w", copyErr)
	}
	if closeErr != nil {
		return Blob{}, fmt.Errorf("close blob: %w", closeErr)
	}
	if written > maxBytes {
		return Blob{}, fmt.Errorf("%w: %d bytes", ErrBlobTooLarge, maxBytes)
	}
	if written == 0 {
		return Blob{}, fmt.Errorf("blob is empty")
	}

	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	hexDigest := hex.EncodeToString(digest[:])
	storageKey := filepath.ToSlash(filepath.Join(hexDigest[0:2], hexDigest))
	destination := filepath.Join(s.root, filepath.FromSlash(storageKey))
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return Blob{}, fmt.Errorf("create blob directory: %w", err)
	}
	if info, err := os.Lstat(destination); err == nil {
		if !info.Mode().IsRegular() || info.Size() != written {
			return Blob{}, fmt.Errorf("existing blob identity has an unexpected file type or size")
		}
		return Blob{SHA256: digest, SizeBytes: written, StorageKey: storageKey}, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return Blob{}, fmt.Errorf("inspect blob destination: %w", err)
	}
	if err := os.Link(temporaryPath, destination); err != nil {
		if info, statErr := os.Lstat(destination); statErr == nil {
			if !info.Mode().IsRegular() || info.Size() != written {
				return Blob{}, fmt.Errorf("concurrent blob publication produced an invalid destination")
			}
			return Blob{SHA256: digest, SizeBytes: written, StorageKey: storageKey}, nil
		}
		return Blob{}, fmt.Errorf("publish blob: %w", err)
	}
	if err := os.Chmod(destination, 0o440); err != nil {
		return Blob{}, fmt.Errorf("make blob read-only: %w", err)
	}
	return Blob{SHA256: digest, SizeBytes: written, StorageKey: storageKey}, nil
}
