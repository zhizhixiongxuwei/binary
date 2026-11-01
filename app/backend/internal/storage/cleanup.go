package storage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// LockPublication spans ingestion and its database commit across all processes
// sharing this blob store. Cleanup takes the exclusive lock so it cannot unlink
// content between an upload's deduplication check and registration of its owner.
func (s *BlobStore) LockPublication(ctx context.Context, exclusive bool) (func(), error) {
	file, err := os.OpenFile(filepath.Join(s.root, ".publication.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	mode := syscall.LOCK_SH
	if exclusive {
		mode = syscall.LOCK_EX
	}
	for {
		err = syscall.Flock(int(file.Fd()), mode|syscall.LOCK_NB)
		if err == nil {
			return func() { _ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN); _ = file.Close() }, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EINTR) {
			file.Close()
			return nil, err
		}
		select {
		case <-ctx.Done():
			file.Close()
			return nil, ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
}

// RemoveTree removes immutable output without following links outside root.
// Published source directories are 0550; their owner needs write permission
// before unlinking children. A missing entry is already successfully cleaned.
func RemoveTree(rootPath, relative string) error {
	cleaned, err := CleanRelativePath(relative)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return err
	}
	defer root.Close()
	return removeRootEntry(root, filepath.FromSlash(cleaned))
}

func removeRootEntry(root *os.Root, name string) error {
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.IsDir() {
		if err := root.Chmod(name, 0o700); err != nil {
			return fmt.Errorf("make cleanup directory writable: %w", err)
		}
		directory, err := root.Open(name)
		if err != nil {
			return err
		}
		entries, err := directory.ReadDir(-1)
		directory.Close()
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if err := removeRootEntry(root, filepath.Join(name, entry.Name())); err != nil {
				return err
			}
		}
	}
	return root.Remove(name)
}
