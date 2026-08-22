package scanner

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"binaryscan.local/backend/internal/identity"
	"binaryscan.local/backend/internal/job"
	"binaryscan.local/backend/internal/storage"
)

type archiveItem struct {
	ordinal      int
	logicalPath  string
	detected     string
	status       string
	blob         storage.Blob
	blobID       string
	fileNodeID   string
	fileNodePath string
}

func (e *Executor) archive(ctx context.Context, claim job.Claim) error {
	subject, format, err := e.loadArchiveSubject(ctx, claim.RunID)
	if err != nil {
		return err
	}
	inputPath, err := e.blobPath(subject.storageKey)
	if err != nil {
		return err
	}
	items, expandedBytes, err := e.readArchive(ctx, inputPath, subject.logicalPath, format)
	if err != nil {
		return err
	}
	return e.jobs.WithFence(ctx, claim, func(tx *sql.Tx) error {
		var published int
		if err := tx.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM archive_entries WHERE import_run_id = ?", claim.RunID).Scan(&published); err != nil {
			return fmt.Errorf("inspect prior archive publication: %w", err)
		}
		if published != 0 {
			return nil
		}
		for _, item := range items {
			var blobID any
			if item.status == "materialized" {
				if _, err := tx.ExecContext(ctx, `INSERT INTO blobs
                    (id, sha256, size_bytes, storage_key, state)
                    VALUES (?, ?, ?, ?, 'ready')
                    ON DUPLICATE KEY UPDATE state = 'ready', deleted_at = NULL`,
					item.blobID, item.blob.SHA256[:], item.blob.SizeBytes, item.blob.StorageKey); err != nil {
					return fmt.Errorf("persist archive blob: %w", err)
				}
				if err := tx.QueryRowContext(ctx, "SELECT id FROM blobs WHERE sha256 = ?", item.blob.SHA256[:]).Scan(&item.blobID); err != nil {
					return fmt.Errorf("resolve archive blob: %w", err)
				}
				blobID = item.blobID
				if _, err := tx.ExecContext(ctx, `INSERT INTO file_nodes
                    (id, task_id, parent_id, blob_id, logical_path, node_kind, detected_format, size_bytes)
                    VALUES (?, ?, ?, ?, ?, 'file', NULLIF(?, ''), ?)`,
					item.fileNodeID, subject.taskID, subject.fileID, item.blobID,
					item.fileNodePath, item.detected, item.blob.SizeBytes); err != nil {
					return fmt.Errorf("publish archive file node: %w", err)
				}
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO archive_entries
                (import_run_id, ordinal, logical_path, size_bytes, detected_format, status, blob_id)
                VALUES (?, ?, ?, ?, NULLIF(?, ''), ?, ?)`,
				claim.RunID, item.ordinal, item.logicalPath, item.blob.SizeBytes,
				item.detected, item.status, blobID); err != nil {
				return fmt.Errorf("record archive entry: %w", err)
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE runs
            SET tool_name = 'binaryscan-archive-importer', tool_version = ? WHERE id = ?`,
			e.cfg.Version, claim.RunID); err != nil {
			return fmt.Errorf("record archive importer: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO task_events
            (task_id, event_type, message, progress_current, progress_total)
            VALUES (?, 'archive.complete', ?, ?, ?)`, subject.taskID,
			fmt.Sprintf("归档导入完成：%d 个条目，%d 字节", len(items), expandedBytes),
			len(items), len(items)); err != nil {
			return fmt.Errorf("record archive completion: %w", err)
		}
		return nil
	})
}

func (e *Executor) loadArchiveSubject(ctx context.Context, runID string) (subject, string, error) {
	var value subject
	var format string
	err := e.db.QueryRowContext(ctx, `SELECT r.task_id, f.id, f.logical_path, b.storage_key, f.detected_format
        FROM runs r
        JOIN tasks t ON t.id = r.task_id AND t.deleted_at IS NULL
        JOIN file_nodes f ON f.id = r.subject_id AND f.task_id = t.id
        JOIN blobs b ON b.id = f.blob_id AND b.state = 'ready'
        WHERE r.id = ? AND r.subject_type = 'file_node' AND r.kind = 'archive_import'`, runID).Scan(
		&value.taskID, &value.fileID, &value.logicalPath, &value.storageKey, &format,
	)
	if err != nil {
		return subject{}, "", fmt.Errorf("load archive input for run %s: %w", runID, err)
	}
	return value, format, nil
}

func (e *Executor) readArchive(
	ctx context.Context, inputPath, sourceName, format string,
) ([]archiveItem, int64, error) {
	switch format {
	case "zip":
		return e.readZip(ctx, inputPath, sourceName)
	case "tar":
		file, err := os.Open(inputPath)
		if err != nil {
			return nil, 0, fmt.Errorf("open tar archive: %w", err)
		}
		defer file.Close()
		return e.readTar(ctx, tar.NewReader(file), sourceName)
	case "gzip":
		file, err := os.Open(inputPath)
		if err != nil {
			return nil, 0, fmt.Errorf("open gzip archive: %w", err)
		}
		defer file.Close()
		reader, err := gzip.NewReader(file)
		if err != nil {
			return nil, 0, fmt.Errorf("open gzip stream: %w", err)
		}
		defer reader.Close()
		lower := strings.ToLower(sourceName)
		if strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz") {
			return e.readTar(ctx, tar.NewReader(reader), sourceName)
		}
		name := strings.TrimSuffix(filepath.Base(sourceName), filepath.Ext(sourceName))
		if name == "" {
			name = "decompressed.bin"
		}
		return e.ingestArchiveReaders(ctx, sourceName,
			[]archiveReader{{ordinal: 1, name: name, size: -1, source: reader}}, e.cfg.Worker.ArchiveMaxBytes)
	default:
		return nil, 0, fmt.Errorf("unsupported archive format %q", format)
	}
}

func (e *Executor) readZip(ctx context.Context, inputPath, sourceName string) ([]archiveItem, int64, error) {
	reader, err := zip.OpenReader(inputPath)
	if err != nil {
		return nil, 0, fmt.Errorf("open zip archive: %w", err)
	}
	defer reader.Close()
	if len(reader.File) > e.cfg.Worker.ArchiveMaxFiles {
		return nil, 0, fmt.Errorf("archive entry limit exceeded")
	}
	entries := make([]archiveReader, 0, len(reader.File))
	for index, file := range reader.File {
		if file.FileInfo().IsDir() {
			continue
		}
		if !file.Mode().IsRegular() {
			entries = append(entries, archiveReader{ordinal: index + 1, name: file.Name, skipped: true})
			continue
		}
		if file.UncompressedSize64 > uint64(e.cfg.Worker.ArchiveMaxBytes) {
			return nil, 0, fmt.Errorf("archive expanded byte limit exceeded")
		}
		entries = append(entries, archiveReader{ordinal: index + 1, name: file.Name, size: int64(file.UncompressedSize64), open: file.Open})
	}
	return e.ingestArchiveReaders(ctx, sourceName, entries, e.cfg.Worker.ArchiveMaxBytes)
}

func (e *Executor) readTar(ctx context.Context, reader *tar.Reader, sourceName string) ([]archiveItem, int64, error) {
	entries := make([]archiveReader, 0)
	seen := make(map[string]struct{})
	var total int64
	for ordinal := 1; ; ordinal++ {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, 0, fmt.Errorf("read tar header: %w", err)
		}
		if ordinal > e.cfg.Worker.ArchiveMaxFiles {
			return nil, 0, fmt.Errorf("archive entry limit exceeded")
		}
		if header.FileInfo().IsDir() {
			continue
		}
		if !header.FileInfo().Mode().IsRegular() || header.Size < 0 {
			entries = append(entries, archiveReader{ordinal: ordinal, name: header.Name, skipped: true})
			continue
		}
		entryName := header.Name
		entrySize := header.Size
		items, expanded, err := e.ingestArchiveReaders(ctx, sourceName,
			[]archiveReader{{ordinal: ordinal, name: entryName, size: entrySize, source: reader}},
			e.cfg.Worker.ArchiveMaxBytes-total)
		if err != nil {
			return nil, 0, err
		}
		if _, duplicate := seen[items[0].logicalPath]; duplicate {
			return nil, 0, fmt.Errorf("archive contains duplicate path %q", items[0].logicalPath)
		}
		seen[items[0].logicalPath] = struct{}{}
		entries = append(entries, archiveReader{materialized: items[0], expanded: expanded})
		total += expanded
	}
	items := make([]archiveItem, 0, len(entries))
	total = 0
	for _, entry := range entries {
		if entry.materialized.status != "" {
			items = append(items, entry.materialized)
			total += entry.expanded
			continue
		}
		item, err := e.skippedArchiveItem(sourceName, entry.ordinal, entry.name)
		if err != nil {
			return nil, 0, err
		}
		items = append(items, item)
	}
	if total > e.cfg.Worker.ArchiveMaxBytes {
		return nil, 0, fmt.Errorf("archive expanded byte limit exceeded")
	}
	return items, total, nil
}

type archiveReader struct {
	ordinal      int
	name         string
	size         int64
	source       io.Reader
	open         func() (io.ReadCloser, error)
	skipped      bool
	materialized archiveItem
	expanded     int64
}

func (e *Executor) ingestArchiveReaders(
	ctx context.Context, sourceName string, entries []archiveReader, maxExpandedBytes int64,
) ([]archiveItem, int64, error) {
	if maxExpandedBytes <= 0 {
		return nil, 0, fmt.Errorf("archive expanded byte limit exceeded")
	}
	items := make([]archiveItem, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))
	var total int64
	for _, entry := range entries {
		logicalPath, fileNodePath, err := archivePaths(sourceName, entry.name)
		if err != nil {
			return nil, 0, err
		}
		if _, duplicate := seen[logicalPath]; duplicate {
			return nil, 0, fmt.Errorf("archive contains duplicate path %q", logicalPath)
		}
		seen[logicalPath] = struct{}{}
		if entry.skipped || entry.size == 0 {
			item, err := e.skippedArchiveItem(sourceName, entry.ordinal, entry.name)
			if err != nil {
				return nil, 0, err
			}
			items = append(items, item)
			continue
		}
		remaining := maxExpandedBytes - total
		if remaining <= 0 || (entry.size > 0 && entry.size > remaining) {
			return nil, 0, fmt.Errorf("archive expanded byte limit exceeded")
		}
		var source io.Reader = entry.source
		var closer io.Closer
		if entry.open != nil {
			opened, err := entry.open()
			if err != nil {
				return nil, 0, fmt.Errorf("open archive entry %q: %w", logicalPath, err)
			}
			source, closer = opened, opened
		}
		blob, ingestErr := e.blobs.Ingest(&contextReader{ctx: ctx, reader: source}, remaining)
		if closer != nil {
			_ = closer.Close()
		}
		if ingestErr != nil {
			if errors.Is(ingestErr, storage.ErrBlobTooLarge) {
				return nil, 0, fmt.Errorf("archive expanded byte limit exceeded")
			}
			return nil, 0, fmt.Errorf("materialize archive entry %q: %w", logicalPath, ingestErr)
		}
		blobID, err := identity.UUID()
		if err != nil {
			return nil, 0, err
		}
		fileNodeID, err := identity.UUID()
		if err != nil {
			return nil, 0, err
		}
		blobPath, err := e.blobPath(blob.StorageKey)
		if err != nil {
			return nil, 0, err
		}
		detected, err := detectFile(blobPath, logicalPath)
		if err != nil {
			return nil, 0, err
		}
		items = append(items, archiveItem{ordinal: entry.ordinal, logicalPath: logicalPath,
			detected: detected, status: "materialized", blob: blob, blobID: blobID,
			fileNodeID: fileNodeID, fileNodePath: fileNodePath})
		total += blob.SizeBytes
	}
	return items, total, nil
}

func (e *Executor) skippedArchiveItem(sourceName string, ordinal int, name string) (archiveItem, error) {
	logicalPath, fileNodePath, err := archivePaths(sourceName, name)
	if err != nil {
		return archiveItem{}, err
	}
	return archiveItem{ordinal: ordinal, logicalPath: logicalPath, fileNodePath: fileNodePath, status: "skipped"}, nil
}

func archivePaths(sourceName, entryName string) (string, string, error) {
	if !utf8.ValidString(entryName) {
		return "", "", fmt.Errorf("archive entry path is not UTF-8")
	}
	cleaned, err := storage.CleanRelativePath(entryName)
	if err != nil {
		return "", "", fmt.Errorf("unsafe archive entry path %q: %w", entryName, err)
	}
	fileNodePath := sourceName + "!/" + cleaned
	if len(fileNodePath) > 1024 {
		return "", "", fmt.Errorf("archive entry path exceeds 1024 characters")
	}
	return cleaned, fileNodePath, nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(buffer []byte) (int, error) {
	select {
	case <-r.ctx.Done():
		return 0, r.ctx.Err()
	default:
		return r.reader.Read(buffer)
	}
}
