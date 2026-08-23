package scanner

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"binaryscan.local/backend/internal/extract"
	"binaryscan.local/backend/internal/filetype"
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
		if _, err := tx.ExecContext(ctx, `UPDATE tasks SET status = 'ready'
			WHERE id = ? AND deleted_at IS NULL`, subject.taskID); err != nil {
			return fmt.Errorf("mark archive task ready: %w", err)
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
	items := make([]archiveItem, 0)
	seen := make(map[string]struct{})
	var total int64
	err := extract.Walk(ctx, inputPath, sourceName, format, e.cfg.Worker.ArchiveMaxFiles,
		func(entry extract.Entry, source io.Reader) error {
			if !entry.Regular {
				name := strings.TrimSpace(entry.Name)
				if name == "." || name == "./" {
					return nil
				}
			}
			logicalPath, fileNodePath, err := archivePaths(sourceName, entry.Name)
			if err != nil {
				return err
			}
			if _, duplicate := seen[logicalPath]; duplicate {
				return fmt.Errorf("archive contains duplicate path %q", logicalPath)
			}
			seen[logicalPath] = struct{}{}
			if !entry.Regular || entry.Size == 0 {
				item, err := e.skippedArchiveItem(sourceName, entry.Ordinal, entry.Name)
				if err != nil {
					return err
				}
				items = append(items, item)
				return nil
			}
			remaining := e.cfg.Worker.ArchiveMaxBytes - total
			if remaining <= 0 || (entry.Size > 0 && entry.Size > remaining) {
				return fmt.Errorf("archive expanded byte limit exceeded")
			}
			blob, ingestErr := e.blobs.Ingest(&contextReader{ctx: ctx, reader: source}, remaining)
			if ingestErr != nil {
				if errors.Is(ingestErr, storage.ErrBlobTooLarge) {
					return fmt.Errorf("archive expanded byte limit exceeded")
				}
				return fmt.Errorf("materialize archive entry %q: %w", logicalPath, ingestErr)
			}
			if entry.Size >= 0 && blob.SizeBytes != entry.Size {
				return fmt.Errorf("archive entry %q size mismatch", logicalPath)
			}
			blobID, err := identity.UUID()
			if err != nil {
				return err
			}
			fileNodeID, err := identity.UUID()
			if err != nil {
				return err
			}
			blobPath, err := e.blobPath(blob.StorageKey)
			if err != nil {
				return err
			}
			detected, err := filetype.Detect(blobPath, logicalPath)
			if err != nil {
				return err
			}
			items = append(items, archiveItem{ordinal: entry.Ordinal, logicalPath: logicalPath,
				detected: detected.Format, status: "materialized", blob: blob, blobID: blobID,
				fileNodeID: fileNodeID, fileNodePath: fileNodePath})
			total += blob.SizeBytes
			return nil
		})
	if err != nil {
		return nil, 0, err
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
