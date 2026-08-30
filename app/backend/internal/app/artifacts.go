package app

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"binaryscan.local/backend/internal/storage"

	"github.com/gin-gonic/gin"
)

// runArtifactRecord 是运行级不可变制品的公开元数据；storage_key 永不暴露给客户端。
type runArtifactRecord struct {
	ID            string          `json:"id"`
	TaskID        string          `json:"taskId"`
	RunID         string          `json:"runId"`
	Kind          string          `json:"kind"`
	MediaType     string          `json:"mediaType"`
	SHA256        string          `json:"sha256,omitempty"`
	SizeBytes     int64           `json:"sizeBytes"`
	SchemaVersion string          `json:"schemaVersion,omitempty"`
	State         string          `json:"state"`
	Metadata      json.RawMessage `json:"metadata,omitempty"`
}

// listRunArtifacts 通过 run/task 关联和未删除任务共同限定可见范围，只列出 ready 且未软删除的制品。
func (s *taskService) listRunArtifacts(c *gin.Context) {
	rows, err := s.db.QueryContext(c, `SELECT a.id, a.task_id, a.run_id, a.artifact_kind,
		a.media_type, HEX(a.sha256), a.size_bytes, a.schema_version, a.state, a.metadata
		FROM run_artifacts a
		JOIN runs r ON r.id = a.run_id AND r.task_id = a.task_id
		JOIN tasks t ON t.id = a.task_id AND t.deleted_at IS NULL
		WHERE a.task_id = ? AND a.run_id = ? AND a.state = 'ready' AND a.deleted_at IS NULL
		ORDER BY a.created_at, a.id`, c.Param("taskID"), c.Param("runID"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "artifact_query_failed"})
		return
	}
	defer rows.Close()
	artifacts := make([]runArtifactRecord, 0)
	for rows.Next() {
		var artifact runArtifactRecord
		var sha, schema sql.NullString
		var metadata []byte
		if err := rows.Scan(&artifact.ID, &artifact.TaskID, &artifact.RunID, &artifact.Kind,
			&artifact.MediaType, &sha, &artifact.SizeBytes, &schema, &artifact.State, &metadata); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "artifact_query_failed"})
			return
		}
		artifact.SHA256 = strings.ToLower(sha.String)
		artifact.SchemaVersion = schema.String
		if len(metadata) > 0 {
			artifact.Metadata = json.RawMessage(metadata)
		}
		artifacts = append(artifacts, artifact)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "artifact_query_failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"artifacts": artifacts})
}

// downloadRunArtifact 将数据库记录作为完整性锚：先清洗内部 storage_key，再拒绝链接/非普通文件，
// 校验长度并在有摘要时复算 SHA-256。下载名仅由经过字符白名单收敛的 artifact kind 生成，
// 防止内部元数据进入 Content-Disposition 时形成响应头注入或不安全文件名。
func (s *taskService) downloadRunArtifact(c *gin.Context) {
	var storageKey, mediaType, kind string
	var size int64
	var expectedSHA sql.NullString
	err := s.db.QueryRowContext(c, `SELECT a.storage_key, a.media_type, a.artifact_kind,
		a.size_bytes, HEX(a.sha256) FROM run_artifacts a
		JOIN tasks t ON t.id = a.task_id AND t.deleted_at IS NULL
		WHERE a.id = ? AND a.task_id = ? AND a.state = 'ready' AND a.deleted_at IS NULL`,
		c.Param("artifactID"), c.Param("taskID")).Scan(
		&storageKey, &mediaType, &kind, &size, &expectedSHA,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "artifact_not_found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "artifact_query_failed"})
		}
		return
	}
	cleaned, err := storage.CleanRelativePath(storageKey)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "artifact_storage_corrupt"})
		return
	}
	filename := filepath.Join(s.storageRoot, "artifacts", filepath.FromSlash(cleaned))
	info, err := os.Lstat(filename)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() != size {
		c.JSON(http.StatusConflict, gin.H{"error": "artifact_storage_corrupt"})
		return
	}
	if expectedSHA.Valid && expectedSHA.String != "" {
		body, readErr := os.ReadFile(filename)
		if readErr != nil || !strings.EqualFold(fmt.Sprintf("%x", sha256.Sum256(body)), expectedSHA.String) {
			c.JSON(http.StatusConflict, gin.H{"error": "artifact_storage_corrupt"})
			return
		}
		c.Header("ETag", `"`+strings.ToLower(expectedSHA.String)+`"`)
	}
	name := strings.Map(func(character rune) rune {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '-' || character == '_' || character == '.' {
			return character
		}
		return '-'
	}, kind)
	if name == "" {
		name = "artifact"
	}
	c.Header("Content-Type", mediaType)
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", name))
	c.File(filename)
}
