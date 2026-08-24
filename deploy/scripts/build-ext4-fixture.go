package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	diskfile "github.com/diskfs/go-diskfs/backend/file"
	"github.com/diskfs/go-diskfs/filesystem/ext4"
	"github.com/google/uuid"
)

const imageSize = int64(32 << 20)

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: build-ext4-fixture OUTPUT ELF PE")
		os.Exit(2)
	}
	if err := build(os.Args[1], os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "build EXT4 fixture:", err)
		os.Exit(1)
	}
}

func build(output string, inputs []string) error {
	storage, err := diskfile.CreateFromPath(output, imageSize)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			_ = storage.Close()
		}
	}()
	filesystemID := uuid.MustParse("8d6e5e27-9e35-4f2d-aef0-4f35d1934a24")
	filesystem, err := ext4.Create(storage, imageSize, 0, 512, &ext4.Params{
		UUID:       &filesystemID,
		VolumeName: "BINARYSCAN",
	})
	if err != nil {
		return err
	}
	for _, input := range inputs {
		if err := copyFile(filesystem, filepath.Base(input), input); err != nil {
			_ = filesystem.Close()
			return err
		}
	}
	if err := filesystem.Close(); err != nil {
		return err
	}
	if err := storage.Close(); err != nil {
		return err
	}
	closed = true
	return nil
}

func copyFile(filesystem *ext4.FileSystem, name, sourcePath string) error {
	source, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer source.Close()
	destination, err := filesystem.OpenFile(name, os.O_CREATE|os.O_RDWR)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(destination, source)
	closeErr := destination.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}
