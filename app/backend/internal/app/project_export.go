package app

import (
	"archive/zip"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"binaryscan.local/backend/internal/storage"
	"github.com/gin-gonic/gin"
)

type projectExportFile struct {
	Name string         `json:"name"`
	Path string         `json:"-"`
	Size sql.NullInt64  `json:"-"`
	SHA  sql.NullString `json:"-"`
}

type projectExportIssue struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

const projectExportTimeout = 15 * time.Minute

func setProjectExportDeadline(writer http.ResponseWriter) error {
	return http.NewResponseController(writer).SetWriteDeadline(time.Now().Add(projectExportTimeout))
}

// Build a complete point-in-time metadata snapshot on disk before sending headers.
// Unlike the UI endpoints, this export does not paginate or discard diagnostics.
func (s *taskService) downloadProjectExport(c *gin.Context) {
	taskID := c.Param("taskID")
	var exists int
	if err := s.db.QueryRowContext(c, "SELECT 1 FROM tasks WHERE id = ? AND deleted_at IS NULL", taskID).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "task_not_found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "project_export_failed"})
		}
		return
	}
	// ZIP construction and large binary transfers can exceed the normal API's
	// 60-second write deadline. Gin unwraps to the real HTTP connection; scope
	// the longer deadline and cancellation budget to this authenticated export.
	if err := setProjectExportDeadline(c.Writer); err != nil && !errors.Is(err, http.ErrNotSupported) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "project_export_failed"})
		return
	}
	defer http.NewResponseController(c.Writer).SetWriteDeadline(time.Time{})
	ctx, cancel := context.WithTimeout(c.Request.Context(), projectExportTimeout)
	defer cancel()
	file, err := os.CreateTemp(filepath.Join(s.reportRoot, ".staging"), "project-export-*.zip")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "project_export_failed"})
		return
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err := s.writeProjectExport(ctx, file, taskID); err != nil {
		slog.Error("project export failed", "request_id", c.GetString("requestID"), "task_id", taskID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "project_export_failed"})
		return
	}
	info, err := file.Stat()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "project_export_failed"})
		return
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "project_export_failed"})
		return
	}
	c.Header("Cache-Control", "no-store")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"binaryscan-project-%s.zip\"", exportName(taskID)))
	c.DataFromReader(http.StatusOK, info.Size(), "application/zip", file, nil)
}

func (s *taskService) writeProjectExport(ctx context.Context, target io.Writer, taskID string) (err error) {
	archive := zip.NewWriter(target)
	defer func() { err = errors.Join(err, archive.Close()) }()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	queries := []struct{ name, query string }{
		{"task", "SELECT * FROM tasks WHERE id = ? AND deleted_at IS NULL"},
		{"runs", "SELECT * FROM runs WHERE task_id = ? ORDER BY created_at, id"},
		{"jobs", "SELECT j.* FROM jobs j JOIN runs r ON r.id = j.run_id WHERE r.task_id = ? ORDER BY j.id"},
		{"job-attempts", "SELECT a.* FROM job_attempts a JOIN jobs j ON j.id = a.job_id JOIN runs r ON r.id = j.run_id WHERE r.task_id = ? ORDER BY a.job_id, a.attempt_number"},
		{"events", "SELECT * FROM task_events WHERE task_id = ? ORDER BY id"},
		{"findings", "SELECT * FROM findings WHERE task_id = ? ORDER BY id"},
		{"file-nodes", "SELECT * FROM file_nodes WHERE task_id = ? ORDER BY id"},
		{"projects", "SELECT * FROM source_projects WHERE task_id = ? ORDER BY id"},
		{"source-files", "SELECT sf.* FROM source_files sf JOIN source_projects p ON p.id = sf.source_project_id WHERE p.task_id = ? ORDER BY sf.id"},
		{"symbols", "SELECT ss.* FROM source_symbols ss JOIN source_projects p ON p.id = ss.source_project_id WHERE p.task_id = ? ORDER BY ss.id"},
		{"artifacts", "SELECT * FROM run_artifacts WHERE task_id = ? ORDER BY id"},
		// Match idx_reports_task_time. Sorting full report snapshots by id can
		// exhaust MySQL's sort buffer even for a few large analysis summaries.
		{"reports", "SELECT * FROM reports WHERE task_id = ? ORDER BY created_at, id"},
		{"archive-entries", "SELECT a.* FROM archive_entries a JOIN runs r ON r.id = a.import_run_id WHERE r.task_id = ? ORDER BY a.id"},
		{"explanations", "SELECT * FROM llm_explanations WHERE task_id = ? ORDER BY created_at, id"},
		{"project-insights", "SELECT i.* FROM llm_project_insights i JOIN source_projects p ON p.id = i.source_project_id WHERE p.task_id = ? ORDER BY i.source_project_id, i.created_at"},
	}
	for _, q := range queries {
		writer, err := archive.Create("metadata/" + q.name + ".json")
		if err != nil {
			return err
		}
		if err := exportRows(ctx, tx, writer, q.query, taskID); err != nil {
			return fmt.Errorf("export %s metadata: %w", q.name, err)
		}
	}
	files := make([]projectExportFile, 0)
	issues := make([]projectExportIssue, 0)
	// Raw tool logs and checker-response JSON include failures, parse errors,
	// coverage, truncation flags and all persisted decompiler diagnostics.
	for _, spec := range []struct{ query, root, prefix string }{
		{"SELECT id, storage_key, size_bytes, HEX(sha256) FROM run_artifacts WHERE task_id = ? AND state = 'ready' AND deleted_at IS NULL ORDER BY id", filepath.Join(s.storageRoot, "artifacts"), "artifacts"},
		{"SELECT id, storage_key, size_bytes, HEX(sha256) FROM reports WHERE task_id = ? AND status = 'ready' AND deleted_at IS NULL ORDER BY id", s.storageRoot, "reports"},
		{"SELECT b.id, b.storage_key, b.size_bytes, HEX(b.sha256) FROM tasks t JOIN blobs b ON b.id=t.blob_id WHERE t.id = ? AND b.state='ready'", filepath.Join(s.storageRoot, "blobs"), "input"},
	} {
		rows, err := tx.QueryContext(ctx, spec.query, taskID)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id, key string
			var entry projectExportFile
			if err := rows.Scan(&id, &key, &entry.Size, &entry.SHA); err != nil {
				rows.Close()
				return err
			}
			entry.Name = spec.prefix + "/" + exportName(id) + "/" + exportName(filepath.Base(filepath.FromSlash(key)))
			entry.Path, err = exportStoragePath(spec.root, key)
			if err != nil {
				issues = append(issues, projectExportIssue{entry.Name, "文件不可用或存储路径无效"})
				continue
			}
			files = append(files, entry)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
	}
	rows, err := tx.QueryContext(ctx, "SELECT id, source_kind, root_storage_key FROM source_projects WHERE task_id = ? AND state = 'ready' AND deleted_at IS NULL ORDER BY id", taskID)
	if err != nil {
		return err
	}
	projects := []sourceProjectPath{}
	for rows.Next() {
		var p sourceProjectPath
		if err := rows.Scan(&p.id, &p.sourceKind, &p.storageKey); err != nil {
			rows.Close()
			return err
		}
		projects = append(projects, p)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	if err := tx.Commit(); err != nil {
		return err
	}
	for _, p := range projects {
		prefix := "sources/" + exportName(p.id) + "/"
		root, err := s.sourceProjectRoot(p)
		if err == nil {
			root, err = exportStoragePath(filepath.Join(s.storageRoot, "projects", p.sourceKind), p.storageKey)
		}
		if err != nil {
			issues = append(issues, projectExportIssue{prefix, "源码已清理或不可用"})
			continue
		}
		// Include project.json and auxiliary maps/logs as well as source files.
		err = filepath.WalkDir(root, func(filename string, entry os.DirEntry, walkErr error) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if walkErr != nil {
				issues = append(issues, projectExportIssue{prefix, "部分源码文件不可读"})
				return nil
			}
			rel, err := filepath.Rel(root, filename)
			if err != nil {
				return err
			}
			if entry.Type()&os.ModeSymlink != 0 {
				issues = append(issues, projectExportIssue{prefix + filepath.ToSlash(rel), "已跳过符号链接"})
				return nil
			}
			if entry.IsDir() {
				return nil
			}
			clean, err := storage.CleanRelativePath(filepath.ToSlash(rel))
			if err != nil {
				return err
			}
			files = append(files, projectExportFile{Name: prefix + clean, Path: filename})
			return nil
		})
		if err != nil {
			return err
		}
	}
	included := make([]string, 0, len(files))
	for _, entry := range files {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := verifyReportFile(entry.Path, entry.Size, entry.SHA); err != nil {
			issues = append(issues, projectExportIssue{entry.Name, "文件缺失、已清理或完整性校验失败"})
			continue
		}
		writer, err := archive.Create(entry.Name)
		if err != nil {
			return err
		}
		if err := copyArchiveSource(ctx, writer, entry.Path); err != nil {
			return err
		}
		included = append(included, entry.Name)
	}
	writer, err := archive.Create("export-manifest.json")
	if err != nil {
		return err
	}
	return json.NewEncoder(writer).Encode(gin.H{"version": "project-export-v1", "taskId": taskID, "exportedAt": time.Now().UTC(), "files": included, "unavailable": issues, "note": "包含导出时已持久化的全部任务元数据、运行记录、事件、检测证据、工具日志、源码和报告。正在运行的任务可能继续产生新数据；已清理或未持久化的信息无法恢复。"})
}

func exportStoragePath(root, key string) (string, error) {
	clean, err := storage.CleanRelativePath(key)
	if err != nil {
		return "", err
	}
	filename := filepath.Join(root, filepath.FromSlash(clean))
	// Reject links in every component, including parent directories.
	current := root
	for _, part := range strings.Split(clean, "/") {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("linked export path")
		}
	}
	return filename, nil
}

func exportName(value string) string {
	result := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			return r
		}
		return '-'
	}, value)
	if result == "" || result == "." || result == ".." {
		return "file"
	}
	return result
}

// Stream rows so large projects do not require an unbounded JSON buffer.
func exportRows(ctx context.Context, tx *sql.Tx, writer io.Writer, query, taskID string) error {
	rows, err := tx.QueryContext(ctx, query, taskID)
	if err != nil {
		return err
	}
	defer rows.Close()
	columns, err := rows.ColumnTypes()
	if err != nil {
		return err
	}
	if _, err := io.WriteString(writer, "[\n"); err != nil {
		return err
	}
	first := true
	for rows.Next() {
		values := make([]any, len(columns))
		dest := make([]any, len(columns))
		for i := range values {
			dest[i] = &values[i]
		}
		if err := rows.Scan(dest...); err != nil {
			return err
		}
		row := make(map[string]any, len(columns))
		for i, column := range columns {
			name := column.Name()
			if name == "storage_key" || name == "root_storage_key" {
				continue
			}
			value := values[i]
			if body, ok := value.([]byte); ok {
				switch column.DatabaseTypeName() {
				case "JSON":
					if json.Valid(body) {
						value = json.RawMessage(body)
					} else {
						value = string(body)
					}
				case "BINARY", "VARBINARY":
					value = hex.EncodeToString(body)
				default:
					value = string(body)
				}
			}
			row[name] = value
		}
		if !first {
			if _, err := io.WriteString(writer, ",\n"); err != nil {
				return err
			}
		}
		first = false
		if err := json.NewEncoder(writer).Encode(row); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_, err = io.WriteString(writer, "]\n")
	return err
}
