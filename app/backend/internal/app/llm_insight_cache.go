package app

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"binaryscan.local/backend/internal/llm"
	"github.com/gin-gonic/gin"
)

type architectureCoverage struct {
	TotalFiles   int  `json:"totalFiles"`
	IndexedFiles int  `json:"indexedFiles"`
	SampledFiles int  `json:"sampledFiles"`
	InputChars   int  `json:"inputChars"`
	Truncated    bool `json:"truncated"`
}

func coverageForArchitecture(source insightContext) architectureCoverage {
	return architectureCoverage{source.TotalFiles, source.IndexedFiles, source.SampledFiles, source.InputChars, source.Truncated}
}

type projectInsightRecord struct {
	Kind      string               `json:"kind"`
	Query     string               `json:"query"`
	Result    insightResult        `json:"result"`
	Coverage  architectureCoverage `json:"coverage"`
	Model     string               `json:"model"`
	CreatedAt time.Time            `json:"createdAt"`
}

type projectInsightCache interface {
	Get(context.Context, explanationTarget, llm.Snapshot) (projectInsightRecord, error)
	Put(context.Context, explanationTarget, llm.Snapshot, projectInsightRecord) error
}
type sqlProjectInsightCache struct{ db *sql.DB }

func (c sqlProjectInsightCache) digest(ctx context.Context, target explanationTarget, settings llm.Snapshot) ([32]byte, error) {
	var manifest string
	err := c.db.QueryRowContext(ctx, `SELECT COALESCE(LOWER(HEX(p.manifest_sha256)), '')
        FROM source_projects p JOIN tasks t ON t.id = p.task_id AND t.deleted_at IS NULL
        WHERE p.id = ? AND p.task_id = ? AND p.state = 'ready'`, target.ProjectID, target.TaskID).Scan(&manifest)
	if errors.Is(err, sql.ErrNoRows) {
		return [32]byte{}, llmFailure("source_project_not_found", "源码项目不存在或已删除。", 404)
	}
	if err != nil {
		return [32]byte{}, err
	}
	value := fmt.Sprintf("architecture-v2\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%d\x00%d", target.ProjectID, manifest, settings.Provider, settings.BaseURL, settings.Model, settings.APIKey, settings.MaxInputChars, settings.MaxOutputTokens)
	return sha256.Sum256([]byte(value)), nil
}

func (c sqlProjectInsightCache) Get(ctx context.Context, target explanationTarget, settings llm.Snapshot) (projectInsightRecord, error) {
	var record projectInsightRecord
	digest, err := c.digest(ctx, target, settings)
	if err != nil {
		return record, err
	}
	var resultJSON, coverageJSON []byte
	err = c.db.QueryRowContext(ctx, `SELECT result_json, coverage_json, model, created_at
        FROM llm_project_insights WHERE source_project_id = ? AND cache_key = ?`, target.ProjectID, digest[:]).Scan(&resultJSON, &coverageJSON, &record.Model, &record.CreatedAt)
	if err != nil {
		return record, err
	}
	if json.Unmarshal(resultJSON, &record.Result) != nil || json.Unmarshal(coverageJSON, &record.Coverage) != nil {
		return record, invalidInsightOutput()
	}
	record.Kind = "architecture"
	return record, nil
}

func (c sqlProjectInsightCache) Put(ctx context.Context, target explanationTarget, settings llm.Snapshot, record projectInsightRecord) error {
	digest, err := c.digest(ctx, target, settings)
	if err != nil {
		return err
	}
	resultJSON, err := json.Marshal(record.Result)
	if err != nil {
		return err
	}
	coverageJSON, err := json.Marshal(record.Coverage)
	if err != nil {
		return err
	}
	_, err = c.db.ExecContext(ctx, `INSERT INTO llm_project_insights
        (source_project_id, cache_key, provider, model, result_json, coverage_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE result_json = VALUES(result_json), coverage_json = VALUES(coverage_json), created_at = VALUES(created_at)`,
		target.ProjectID, digest[:], settings.Provider, settings.Model, resultJSON, coverageJSON, record.CreatedAt)
	return err
}

func (s *llmService) getInsight(c *gin.Context) {
	if kind := c.Query("kind"); kind != "" && kind != "architecture" {
		writeLLMError(c, llmFailure("invalid_request", "当前只支持读取架构图缓存。", 400))
		return
	}
	if s.insightCache == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "insight_not_found"})
		return
	}
	record, err := s.insightCache.Get(c.Request.Context(), targetFromContext(c), s.manager.Snapshot())
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "insight_not_found"})
		return
	}
	if err != nil {
		writeLLMError(c, err)
		return
	}
	c.JSON(http.StatusOK, record)
}
