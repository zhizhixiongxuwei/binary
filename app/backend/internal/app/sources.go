package app

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"binaryscan.local/backend/internal/storage"

	"github.com/gin-gonic/gin"
)

const maxSourcePreviewBytes = 16 << 20

const maxSourceFileContentBytes = 4 << 20

type sourceProjectPath struct {
	id         string
	sourceKind string
	storageKey string
}

type sourceFileRecord struct {
	ID          string `json:"id"`
	ProjectID   string `json:"projectId"`
	LogicalPath string `json:"logicalPath"`
	Language    string `json:"language"`
	MediaType   string `json:"-"`
	SHA256      string `json:"sha256"`
	SizeBytes   int64  `json:"sizeBytes"`
	LineCount   int    `json:"lineCount"`
}

func (s *taskService) downloadProject(c *gin.Context) {
	project, err := s.loadSourceProject(c, c.Param("taskID"), c.Param("projectID"))
	if err != nil {
		sourceProjectError(c, err)
		return
	}
	body, err := s.zipProjects([]sourceProjectPath{project}, false)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "source_export_failed"})
		return
	}
	c.Header("Content-Type", "application/zip")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"binaryscan-project-%s.zip\"", project.id))
	c.Data(http.StatusOK, "application/zip", body)
}

func (s *taskService) downloadSources(c *gin.Context) {
	projects, err := s.loadTaskSourceProjects(c, c.Param("taskID"))
	if err != nil {
		sourceProjectError(c, err)
		return
	}
	if len(projects) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "source_project_not_found"})
		return
	}
	body, err := s.zipProjects(projects, c.Query("combined") == "1")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "source_export_failed"})
		return
	}
	c.Header("Content-Type", "application/zip")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"binaryscan-sources-%s.zip\"", c.Param("taskID")))
	c.Data(http.StatusOK, "application/zip", body)
}

func (s *taskService) sourcePreview(c *gin.Context) {
	project, err := s.loadSourceProject(c, c.Param("taskID"), c.Param("projectID"))
	if err != nil {
		sourceProjectError(c, err)
		return
	}
	root, err := s.sourceProjectRoot(project)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "source_storage_invalid"})
		return
	}
	body, err := concatenateSourceFiles(root, maxSourcePreviewBytes)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "source_read_failed"})
		return
	}
	offset := boundedQueryInt(c.Query("offset"), 0, len(body), 0)
	limit := boundedQueryInt(c.Query("limit"), 1, 1<<20, 256<<10)
	end := offset + limit
	if end > len(body) {
		end = len(body)
	}
	result := gin.H{
		"result_id": project.id, "offset": offset, "content": string(body[offset:end]),
		"complete": end == len(body), "sha256": "", "size_bytes": len(body),
	}
	if end < len(body) {
		result["next_offset"] = end
	}
	c.JSON(http.StatusOK, result)
}

func (s *taskService) listProjectSourceFiles(c *gin.Context) {
	rows, err := s.db.QueryContext(c, `SELECT sf.id, sf.source_project_id, sf.logical_path,
		sf.language, sf.media_type, HEX(sf.sha256), sf.size_bytes, sf.line_count
		FROM source_files sf
		JOIN source_projects p ON p.id = sf.source_project_id AND p.state = 'ready'
		JOIN tasks t ON t.id = p.task_id AND t.deleted_at IS NULL
		WHERE p.id = ? AND p.task_id = ? AND sf.state = 'ready'
		ORDER BY sf.logical_path, sf.id LIMIT 5000`, c.Param("projectID"), c.Param("taskID"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "source_file_query_failed"})
		return
	}
	defer rows.Close()
	files := make([]sourceFileRecord, 0)
	for rows.Next() {
		var file sourceFileRecord
		if err := rows.Scan(&file.ID, &file.ProjectID, &file.LogicalPath, &file.Language,
			&file.MediaType, &file.SHA256, &file.SizeBytes, &file.LineCount); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "source_file_query_failed"})
			return
		}
		file.SHA256 = strings.ToLower(file.SHA256)
		files = append(files, file)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "source_file_query_failed"})
		return
	}
	if len(files) == 0 {
		var exists int
		if err := s.db.QueryRowContext(c, `SELECT 1 FROM source_projects p
			JOIN tasks t ON t.id = p.task_id AND t.deleted_at IS NULL
			WHERE p.id = ? AND p.task_id = ? AND p.state = 'ready'`,
			c.Param("projectID"), c.Param("taskID")).Scan(&exists); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				c.JSON(http.StatusNotFound, gin.H{"error": "source_project_not_found"})
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "source_file_query_failed"})
			}
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{"files": files})
}

func (s *taskService) sourceFileContent(c *gin.Context) {
	var project sourceProjectPath
	var file sourceFileRecord
	err := s.db.QueryRowContext(c, `SELECT p.id, p.source_kind, p.root_storage_key,
		sf.id, sf.source_project_id, sf.logical_path, sf.language, sf.media_type,
		HEX(sf.sha256), sf.size_bytes, sf.line_count
		FROM source_projects p
		JOIN source_files sf ON sf.source_project_id = p.id AND sf.state = 'ready'
		JOIN tasks t ON t.id = p.task_id AND t.deleted_at IS NULL
		WHERE p.id = ? AND p.task_id = ? AND sf.id = ? AND p.state = 'ready'`,
		c.Param("projectID"), c.Param("taskID"), c.Param("fileID")).Scan(
		&project.id, &project.sourceKind, &project.storageKey,
		&file.ID, &file.ProjectID, &file.LogicalPath, &file.Language, &file.MediaType,
		&file.SHA256, &file.SizeBytes, &file.LineCount)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "source_file_not_found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "source_file_query_failed"})
		}
		return
	}
	if file.SizeBytes > maxSourceFileContentBytes {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "source_file_too_large"})
		return
	}
	root, err := s.sourceProjectRoot(project)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "source_storage_corrupt"})
		return
	}
	cleaned, err := storage.CleanRelativePath(file.LogicalPath)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "source_storage_corrupt"})
		return
	}
	filename := filepath.Join(root, filepath.FromSlash(cleaned))
	info, err := os.Lstat(filename)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() != file.SizeBytes {
		c.JSON(http.StatusConflict, gin.H{"error": "source_storage_corrupt"})
		return
	}
	body, err := os.ReadFile(filename)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "source_storage_corrupt"})
		return
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(body))
	if !strings.EqualFold(digest, file.SHA256) {
		c.JSON(http.StatusConflict, gin.H{"error": "source_storage_corrupt"})
		return
	}
	file.SHA256 = strings.ToLower(file.SHA256)
	c.Header("ETag", `"`+file.SHA256+`"`)
	c.JSON(http.StatusOK, gin.H{
		"id": file.ID, "projectId": file.ProjectID, "logicalPath": file.LogicalPath,
		"language": file.Language, "sha256": file.SHA256,
		"sizeBytes": file.SizeBytes, "lineCount": file.LineCount, "content": string(body),
	})
}

func boundedQueryInt(raw string, minimum, maximum, fallback int) int {
	value, err := strconv.Atoi(raw)
	if err != nil || value < minimum {
		return fallback
	}
	if value > maximum {
		return maximum
	}
	return value
}

func (s *taskService) loadSourceProject(ctx *gin.Context, taskID, projectID string) (sourceProjectPath, error) {
	var project sourceProjectPath
	err := s.db.QueryRowContext(ctx, `SELECT p.id, p.source_kind, p.root_storage_key FROM source_projects p
		JOIN tasks t ON t.id = p.task_id AND t.deleted_at IS NULL
		WHERE p.id = ? AND p.task_id = ? AND p.state = 'ready'`, projectID, taskID).Scan(&project.id, &project.sourceKind, &project.storageKey)
	return project, err
}

func (s *taskService) loadTaskSourceProjects(ctx *gin.Context, taskID string) ([]sourceProjectPath, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT p.id, p.source_kind, p.root_storage_key FROM source_projects p
		JOIN tasks t ON t.id = p.task_id AND t.deleted_at IS NULL
		WHERE p.task_id = ? AND p.state = 'ready' ORDER BY p.created_at`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	projects := make([]sourceProjectPath, 0)
	for rows.Next() {
		var project sourceProjectPath
		if err := rows.Scan(&project.id, &project.sourceKind, &project.storageKey); err != nil {
			return nil, err
		}
		projects = append(projects, project)
	}
	return projects, rows.Err()
}

func sourceProjectError(c *gin.Context, err error) {
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "source_project_not_found"})
		return
	}
	c.JSON(http.StatusInternalServerError, gin.H{"error": "source_project_query_failed"})
}

func (s *taskService) sourceProjectRoot(project sourceProjectPath) (string, error) {
	key, err := storage.CleanRelativePath(project.storageKey)
	if err != nil {
		return "", err
	}
	kind, err := storage.CleanRelativePath(project.sourceKind)
	if err != nil || (kind != "native" && kind != "jvm" && kind != "pyc") {
		return "", fmt.Errorf("invalid source kind")
	}
	root := filepath.Join(s.storageRoot, "projects", kind, filepath.FromSlash(key))
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("source project unavailable")
	}
	return root, nil
}

func sourceFiles(root string) ([]string, error) {
	files := make([]string, 0)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return filepath.SkipDir
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		cleaned, err := storage.CleanRelativePath(filepath.ToSlash(relative))
		if err != nil {
			return err
		}
		if cleaned != "project.json" {
			files = append(files, cleaned)
		}
		return nil
	})
	sort.Strings(files)
	return files, err
}

func concatenateSourceFiles(root string, limit int64) ([]byte, error) {
	files, err := sourceFiles(root)
	if err != nil {
		return nil, err
	}
	var output bytes.Buffer
	for _, relative := range files {
		header := []byte("\n\n/* ===== " + relative + " ===== */\n")
		if int64(output.Len()+len(header)) > limit {
			break
		}
		output.Write(header)
		file, err := os.Open(filepath.Join(root, filepath.FromSlash(relative)))
		if err != nil {
			return nil, err
		}
		remaining := limit - int64(output.Len())
		_, copyErr := io.Copy(&output, io.LimitReader(file, remaining))
		closeErr := file.Close()
		if copyErr != nil {
			return nil, copyErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if int64(output.Len()) >= limit {
			break
		}
	}
	return output.Bytes(), nil
}

func (s *taskService) zipProjects(projects []sourceProjectPath, combined bool) ([]byte, error) {
	var body bytes.Buffer
	archive := zip.NewWriter(&body)
	var combinedC bytes.Buffer
	for _, project := range projects {
		root, err := s.sourceProjectRoot(project)
		if err != nil {
			archive.Close()
			return nil, err
		}
		files, err := sourceFiles(root)
		if err != nil {
			archive.Close()
			return nil, err
		}
		for _, relative := range files {
			content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
			if err != nil {
				archive.Close()
				return nil, err
			}
			writer, err := archive.Create(filepath.ToSlash(filepath.Join(project.id, relative)))
			if err != nil {
				archive.Close()
				return nil, err
			}
			if _, err := writer.Write(content); err != nil {
				archive.Close()
				return nil, err
			}
			if combined && strings.HasSuffix(strings.ToLower(relative), ".c") {
				fmt.Fprintf(&combinedC, "\n\n/* ===== %s/%s ===== */\n", project.id, relative)
				combinedC.Write(content)
			}
		}
	}
	if combined && combinedC.Len() > 0 {
		writer, err := archive.Create("all-functions.c")
		if err != nil {
			archive.Close()
			return nil, err
		}
		if _, err := writer.Write(combinedC.Bytes()); err != nil {
			archive.Close()
			return nil, err
		}
	}
	if err := archive.Close(); err != nil {
		return nil, err
	}
	return body.Bytes(), nil
}
