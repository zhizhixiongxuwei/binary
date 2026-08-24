package extract

import (
	"archive/tar"
	"archive/zip"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	iofs "io/fs"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/bodgit/sevenzip"
	diskfile "github.com/diskfs/go-diskfs/backend/file"
	"github.com/diskfs/go-diskfs/filesystem/iso9660"
	"github.com/klauspost/compress/zstd"
	"github.com/nwaples/rardecode/v2"
	"github.com/sassoftware/go-rpmutils"
	"github.com/ulikunitz/xz"
)

type Entry struct {
	Ordinal int
	Name    string
	Size    int64
	Regular bool
}

type Visitor func(Entry, io.Reader) error

// Walk visits exactly one logical archive layer. Compression wrappers around a
// tar stream (.tar.gz/.tgz and .tar.xz/.txz) count as part of that layer; archive
// members are never recursively expanded.
func Walk(ctx context.Context, filename, sourceName, format string, maxEntries int, visit Visitor) error {
	if maxEntries <= 0 {
		return fmt.Errorf("archive entry limit must be positive")
	}
	switch format {
	case "zip":
		return walkZIP(ctx, filename, maxEntries, visit)
	case "7z":
		return walk7Z(ctx, filename, maxEntries, visit)
	case "rar":
		return walkRAR(ctx, filename, maxEntries, visit)
	case "tar":
		file, err := os.Open(filename)
		if err != nil {
			return fmt.Errorf("open tar archive: %w", err)
		}
		defer file.Close()
		return walkTAR(ctx, tar.NewReader(file), maxEntries, visit)
	case "gzip":
		return walkGZIP(ctx, filename, sourceName, maxEntries, visit)
	case "xz":
		return walkXZ(ctx, filename, sourceName, maxEntries, visit)
	case "deb":
		return walkDebian(ctx, filename, maxEntries, visit)
	case "rpm":
		return walkRPM(ctx, filename, maxEntries, visit)
	case "iso9660":
		return walkISO9660(ctx, filename, maxEntries, visit)
	default:
		return fmt.Errorf("unsupported archive format %q", format)
	}
}

func walkZIP(ctx context.Context, filename string, maxEntries int, visit Visitor) error {
	reader, err := zip.OpenReader(filename)
	if err != nil {
		return fmt.Errorf("open ZIP archive: %w", err)
	}
	defer reader.Close()
	if len(reader.File) > maxEntries {
		return fmt.Errorf("archive entry limit exceeded")
	}
	for index, file := range reader.File {
		entry := Entry{Ordinal: index + 1, Name: file.Name, Size: int64(file.UncompressedSize64), Regular: file.Mode().IsRegular()}
		if !entry.Regular {
			if err := call(ctx, visit, entry, nil); err != nil {
				return err
			}
			continue
		}
		stream, err := file.Open()
		if err != nil {
			return fmt.Errorf("open ZIP member %q: %w", file.Name, err)
		}
		visitErr := call(ctx, visit, entry, stream)
		closeErr := stream.Close()
		if visitErr != nil {
			return visitErr
		}
		if closeErr != nil {
			return fmt.Errorf("close ZIP member %q: %w", file.Name, closeErr)
		}
	}
	return nil
}

func walk7Z(ctx context.Context, filename string, maxEntries int, visit Visitor) error {
	reader, err := sevenzip.OpenReader(filename)
	if err != nil {
		return fmt.Errorf("open 7Z archive: %w", err)
	}
	defer reader.Close()
	if len(reader.File) > maxEntries {
		return fmt.Errorf("archive entry limit exceeded")
	}
	for index, file := range reader.File {
		if file.UncompressedSize > math.MaxInt64 {
			return fmt.Errorf("7Z member %q exceeds supported size", file.Name)
		}
		entry := Entry{Ordinal: index + 1, Name: file.Name, Size: int64(file.UncompressedSize), Regular: file.FileInfo().Mode().IsRegular()}
		if !entry.Regular {
			if err := call(ctx, visit, entry, nil); err != nil {
				return err
			}
			continue
		}
		stream, err := file.Open()
		if err != nil {
			return fmt.Errorf("open 7Z member %q: %w", file.Name, err)
		}
		visitErr := call(ctx, visit, entry, stream)
		closeErr := stream.Close()
		if visitErr != nil {
			return visitErr
		}
		if closeErr != nil {
			return fmt.Errorf("close 7Z member %q: %w", file.Name, closeErr)
		}
	}
	return nil
}

func walkRAR(ctx context.Context, filename string, maxEntries int, visit Visitor) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("open RAR archive: %w", err)
	}
	defer file.Close()
	reader, err := rardecode.NewReader(file)
	if err != nil {
		return fmt.Errorf("initialize RAR reader: %w", err)
	}
	for ordinal := 1; ; ordinal++ {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read RAR member: %w", err)
		}
		if ordinal > maxEntries {
			return fmt.Errorf("archive entry limit exceeded")
		}
		size := header.UnPackedSize
		if header.UnKnownSize {
			size = -1
		}
		entry := Entry{Ordinal: ordinal, Name: header.Name, Size: size, Regular: header.Mode().IsRegular() && !header.IsDir}
		if err := call(ctx, visit, entry, reader); err != nil {
			return err
		}
	}
}

func walkTAR(ctx context.Context, reader *tar.Reader, maxEntries int, visit Visitor) error {
	for ordinal := 1; ; ordinal++ {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read TAR member: %w", err)
		}
		if ordinal > maxEntries {
			return fmt.Errorf("archive entry limit exceeded")
		}
		entry := Entry{Ordinal: ordinal, Name: header.Name, Size: header.Size,
			Regular: header.FileInfo().Mode().IsRegular() && header.Size >= 0}
		if err := call(ctx, visit, entry, reader); err != nil {
			return err
		}
	}
}

func walkGZIP(ctx context.Context, filename, sourceName string, maxEntries int, visit Visitor) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("open GZIP archive: %w", err)
	}
	defer file.Close()
	reader, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("initialize GZIP reader: %w", err)
	}
	defer reader.Close()
	if hasTarGZSuffix(sourceName) {
		return walkTAR(ctx, tar.NewReader(reader), maxEntries, visit)
	}
	return call(ctx, visit, Entry{Ordinal: 1, Name: strippedCompressionName(sourceName, ".gz"), Size: -1, Regular: true}, reader)
}

func walkXZ(ctx context.Context, filename, sourceName string, maxEntries int, visit Visitor) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("open XZ archive: %w", err)
	}
	defer file.Close()
	reader, err := xz.NewReader(file)
	if err != nil {
		return fmt.Errorf("initialize XZ reader: %w", err)
	}
	if hasTarXZSuffix(sourceName) {
		return walkTAR(ctx, tar.NewReader(reader), maxEntries, visit)
	}
	return call(ctx, visit, Entry{Ordinal: 1, Name: strippedCompressionName(sourceName, ".xz"), Size: -1, Regular: true}, reader)
}

func walkDebian(ctx context.Context, filename string, maxEntries int, visit Visitor) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("open DEB package: %w", err)
	}
	defer file.Close()
	var signature [8]byte
	if _, err := io.ReadFull(file, signature[:]); err != nil || string(signature[:]) != "!<arch>\n" {
		return fmt.Errorf("invalid DEB ar signature")
	}
	for ordinal := 1; ; ordinal++ {
		var header [60]byte
		_, err := io.ReadFull(file, header[:])
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("DEB package does not contain a supported data.tar payload")
		}
		if err != nil {
			return fmt.Errorf("read DEB member header: %w", err)
		}
		if string(header[58:60]) != "`\n" {
			return fmt.Errorf("invalid DEB member header")
		}
		name := strings.TrimSuffix(strings.TrimSpace(string(header[:16])), "/")
		size, err := strconv.ParseInt(strings.TrimSpace(string(header[48:58])), 10, 64)
		if err != nil || size < 0 {
			return fmt.Errorf("invalid DEB member size")
		}
		limited := &io.LimitedReader{R: file, N: size}
		if strings.HasPrefix(name, "data.tar") {
			var payload io.Reader = limited
			var closePayload func()
			switch {
			case name == "data.tar":
			case strings.HasSuffix(name, ".gz"):
				reader, err := gzip.NewReader(limited)
				if err != nil {
					return fmt.Errorf("open DEB gzip payload: %w", err)
				}
				payload, closePayload = reader, func() { _ = reader.Close() }
			case strings.HasSuffix(name, ".xz"):
				reader, err := xz.NewReader(limited)
				if err != nil {
					return fmt.Errorf("open DEB xz payload: %w", err)
				}
				payload = reader
			case strings.HasSuffix(name, ".zst") || strings.HasSuffix(name, ".zstd"):
				reader, err := zstd.NewReader(limited)
				if err != nil {
					return fmt.Errorf("open DEB zstd payload: %w", err)
				}
				payload, closePayload = reader, reader.Close
			case strings.HasSuffix(name, ".bz2"):
				payload = bzip2.NewReader(limited)
			default:
				return fmt.Errorf("unsupported DEB data payload %q", name)
			}
			walkErr := walkTAR(ctx, tar.NewReader(payload), maxEntries, visit)
			if closePayload != nil {
				closePayload()
			}
			return walkErr
		}
		if _, err := io.Copy(io.Discard, limited); err != nil {
			return fmt.Errorf("drain DEB member %q: %w", name, err)
		}
		if size%2 != 0 {
			if _, err := file.Seek(1, io.SeekCurrent); err != nil {
				return fmt.Errorf("skip DEB member padding: %w", err)
			}
		}
	}
}

func walkRPM(ctx context.Context, filename string, maxEntries int, visit Visitor) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("open RPM package: %w", err)
	}
	defer file.Close()
	packageFile, err := rpmutils.ReadRpm(file)
	if err != nil {
		return fmt.Errorf("parse RPM package: %w", err)
	}
	// Read the cpio stream directly. PayloadReaderExtended additionally relies
	// on a complete RPM file-metadata tag set (for example FILEUSERNAME), while
	// valid minimal RPMs and older packages may omit those optional tags.
	// Uploaded files are capped below 4 GiB, so the classic cpio reader's size
	// representation is sufficient here.
	payload, err := packageFile.PayloadReader()
	if err != nil {
		return fmt.Errorf("open RPM payload: %w", err)
	}
	for ordinal := 1; ; ordinal++ {
		info, err := payload.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read RPM payload member: %w", err)
		}
		if ordinal > maxEntries {
			return fmt.Errorf("archive entry limit exceeded")
		}
		mode := info.Mode() & 0o170000
		entry := Entry{Ordinal: ordinal, Name: strings.TrimPrefix(info.Filename(), "./"),
			Size: info.Filesize64(), Regular: mode == 0o100000}
		if err := call(ctx, visit, entry, payload); err != nil {
			return err
		}
	}
}

func walkISO9660(ctx context.Context, filename string, maxEntries int, visit Visitor) error {
	storage, err := diskfile.OpenFromPath(filename, true)
	if err != nil {
		return fmt.Errorf("open ISO 9660 image: %w", err)
	}
	defer storage.Close()
	info, err := storage.Stat()
	if err != nil {
		return fmt.Errorf("stat ISO 9660 image: %w", err)
	}
	filesystem, err := iso9660.Read(storage, info.Size(), 0, 0)
	if err != nil {
		return fmt.Errorf("read ISO 9660 filesystem: %w", err)
	}
	defer filesystem.Close()

	ordinal := 0
	err = iofs.WalkDir(filesystem, ".", func(name string, directoryEntry iofs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if name == "." {
			return nil
		}
		ordinal++
		if ordinal > maxEntries {
			return fmt.Errorf("archive entry limit exceeded")
		}
		entryInfo, infoErr := directoryEntry.Info()
		if infoErr != nil {
			return fmt.Errorf("read ISO 9660 member %q metadata: %w", name, infoErr)
		}
		entry := Entry{
			Ordinal: ordinal,
			Name:    strings.TrimPrefix(name, "./"),
			Size:    entryInfo.Size(),
			Regular: entryInfo.Mode().IsRegular(),
		}
		if !entry.Regular {
			return call(ctx, visit, entry, nil)
		}
		stream, openErr := filesystem.Open(name)
		if openErr != nil {
			return fmt.Errorf("open ISO 9660 member %q: %w", name, openErr)
		}
		visitErr := call(ctx, visit, entry, stream)
		closeErr := stream.Close()
		if visitErr != nil {
			return visitErr
		}
		if closeErr != nil {
			return fmt.Errorf("close ISO 9660 member %q: %w", name, closeErr)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("walk ISO 9660 filesystem: %w", err)
	}
	return nil
}

func call(ctx context.Context, visit Visitor, entry Entry, reader io.Reader) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	if reader == nil {
		reader = strings.NewReader("")
	}
	return visit(entry, reader)
}

func hasTarGZSuffix(name string) bool {
	name = strings.ToLower(name)
	return strings.HasSuffix(name, ".tar.gz") || strings.HasSuffix(name, ".tgz")
}

func hasTarXZSuffix(name string) bool {
	name = strings.ToLower(name)
	return strings.HasSuffix(name, ".tar.xz") || strings.HasSuffix(name, ".txz")
}

func strippedCompressionName(sourceName, suffix string) string {
	name := filepath.Base(strings.ReplaceAll(sourceName, "\\", "/"))
	if strings.HasSuffix(strings.ToLower(name), suffix) {
		name = name[:len(name)-len(suffix)]
	}
	if name == "" || name == "." {
		return "decompressed.bin"
	}
	return name
}
