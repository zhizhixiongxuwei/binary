package app

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"binaryscan.local/backend/internal/capability"
	"binaryscan.local/backend/internal/checkrules"
	"binaryscan.local/backend/internal/job"
	"github.com/gin-gonic/gin"
)

type projectRuleCatalog struct {
	Language string `json:"language"`
	Engine   struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"engine"`
	CatalogVersion string            `json:"catalogVersion"`
	Rules          []checkrules.Rule `json:"rules"`
	Freshness      string            `json:"freshness"`
	Available      bool              `json:"available"`
	LastCheckedAt  *time.Time        `json:"last_checked_at"`
	Detail         string            `json:"detail"`
}

func (s *taskService) loadRuleCatalog(c *gin.Context, language string) (projectRuleCatalog, error) {
	result := projectRuleCatalog{Language: language, Freshness: "missing", Rules: []checkrules.Rule{}, Detail: "尚无新鲜规则目录，请等待 Scanner 上报"}
	result.Engine.Name = language + "-checker"
	rows, err := s.db.QueryContext(c, `SELECT report,checked_at,heartbeat_at FROM worker_capabilities WHERE role='scanner' ORDER BY checked_at DESC LIMIT 1000`)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	now := time.Now().UTC()
	ttl := s.capabilityReportTTL
	if ttl <= 0 {
		ttl = 3 * time.Minute
	}
	freshVersions := map[string]bool{}
	chosenFresh := false
	freshUnready := false
	for rows.Next() {
		var body []byte
		var checked, heartbeat time.Time
		if err := rows.Scan(&body, &checked, &heartbeat); err != nil {
			return result, err
		}
		var report capability.Report
		if json.Unmarshal(body, &report) != nil {
			if reportFresh(capabilityRecord{CheckedAt: checked, HeartbeatAt: heartbeat}, now, ttl) {
				freshUnready = true
			}
			continue
		}
		freshRecord := reportFresh(capabilityRecord{CheckedAt: checked, HeartbeatAt: heartbeat}, now, ttl)
		observed := false
		for _, observation := range report.RuleCatalogs {
			if observation.Language != language || observation.Catalog == nil || observation.Status != "available" || observation.Catalog.Validate(language) != nil {
				continue
			}
			observed = true
			fresh := reportFresh(capabilityRecord{CheckedAt: checked, HeartbeatAt: heartbeat}, now, ttl)
			if fresh {
				freshVersions[observation.Catalog.CatalogVersion] = true
			}
			if result.LastCheckedAt == nil || (fresh && !chosenFresh) {
				result.CatalogVersion = observation.Catalog.CatalogVersion
				result.Rules = observation.Catalog.Rules
				value := checked
				result.LastCheckedAt = &value
				result.Engine.Version = ""
				for _, analyzer := range report.Analyzers {
					if analyzer.Name == result.Engine.Name {
						result.Engine.Version = analyzer.Version
						break
					}
				}
				chosenFresh = fresh
				if fresh {
					result.Freshness = "fresh"
					result.Available = true
					result.Detail = "来自 Scanner 的当前规则目录；仅执行本次选择的规则"
				} else {
					result.Freshness = "stale"
					result.Detail = "规则目录探测已过期，需等待 Scanner 更新"
				}
			}
		}
		if freshRecord && !observed {
			freshUnready = true
		}
	}
	if len(freshVersions) > 1 {
		result.Freshness = "conflict"
		result.Available = false
		result.Detail = "多个 Scanner 上报的规则目录版本不一致，暂不可启动检测"
	}
	if freshUnready && len(freshVersions) > 0 {
		result.Freshness = "conflict"
		result.Available = false
		result.Detail = "部分 Scanner 未提供有效规则目录，暂不可保证检测规则一致"
	}
	return result, rows.Err()
}
func (s *taskService) projectCheckRules(c *gin.Context) {
	var language string
	err := s.db.QueryRowContext(c, `SELECT p.language FROM source_projects p JOIN tasks t ON t.id=p.task_id AND t.deleted_at IS NULL WHERE p.id=? AND p.task_id=? AND p.state='ready'`, c.Param("projectID"), c.Param("taskID")).Scan(&language)
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(404, gin.H{"error": "source_project_not_found"})
		return
	}
	if err != nil {
		c.JSON(500, gin.H{"error": "project_query_failed"})
		return
	}
	catalog, err := s.loadRuleCatalog(c, language)
	if err != nil {
		c.JSON(500, gin.H{"error": "rule_catalog_query_failed"})
		return
	}
	c.JSON(200, catalog)
}

type checkSelectionInput struct {
	IDs     []string
	Version string
	All     bool
}

func readCheckSelection(c *gin.Context) (checkSelectionInput, error) {
	body, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, 64<<10))
	if err != nil {
		return checkSelectionInput{}, checkrules.ErrSelection
	}
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return checkSelectionInput{All: true}, nil
	}
	if body[0] != '{' {
		return checkSelectionInput{}, checkrules.ErrSelection
	}
	var input struct {
		IDs     json.RawMessage `json:"ruleIds"`
		Version *string         `json:"catalogVersion"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return checkSelectionInput{}, checkrules.ErrSelection
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) == nil && len(fields) == 0 {
		return checkSelectionInput{All: true}, nil
	}
	if input.Version == nil || len(input.IDs) == 0 || string(input.IDs) == "null" {
		return checkSelectionInput{}, checkrules.ErrSelection
	}
	var ids []string
	if json.Unmarshal(input.IDs, &ids) != nil {
		return checkSelectionInput{}, checkrules.ErrSelection
	}
	ids, err = checkrules.Normalize(ids)
	if err != nil {
		return checkSelectionInput{}, err
	}
	return checkSelectionInput{IDs: ids, Version: *input.Version}, nil
}

var errRunIntentConflict = errors.New("run idempotency conflict")

func (s *taskService) queueCheckRules(c *gin.Context, taskID, projectID, language string, kind job.Kind) {
	key := strings.TrimSpace(c.GetHeader("Idempotency-Key"))
	if !validIdempotencyKey(key) {
		c.JSON(400, gin.H{"error": "idempotency_key_required"})
		return
	}
	input, err := readCheckSelection(c)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid_rule_selection"})
		return
	}
	var existing queuedRun
	var request []byte
	err = s.db.QueryRowContext(c, `SELECT id,kind,status,created_at,request FROM runs WHERE created_by=? AND kind=? AND subject_id=? AND idempotency_key=?`, mustCurrentUser(c).ID, kind, projectID, key).Scan(&existing.ID, &existing.Kind, &existing.Status, &existing.CreatedAt, &request)
	if err == nil {
		existing.Selection, err = checkrules.FromRequest(request)
		matches := err == nil
		if input.All {
			matches = matches && (existing.Selection == nil || existing.Selection.Mode == "all")
		} else {
			matches = matches && existing.Selection != nil && existing.Selection.CatalogVersion == input.Version && equalRuleIDs(existing.Selection.EnabledRuleIDs, input.IDs)
		}
		if !matches {
			c.JSON(409, gin.H{"error": "run_idempotency_conflict"})
			return
		}
		c.JSON(200, gin.H{"run": existing})
		return
	}
	if !errors.Is(err, sql.ErrNoRows) {
		c.JSON(500, gin.H{"error": "run_creation_failed"})
		return
	}
	directory, err := s.loadRuleCatalog(c, language)
	if err != nil {
		c.JSON(500, gin.H{"error": "rule_catalog_query_failed"})
		return
	}
	if !directory.Available {
		code, status := "rule_catalog_unavailable", 503
		if directory.Freshness == "stale" {
			code, status = "rule_catalog_stale", 409
		}
		if directory.Freshness == "conflict" {
			code, status = "rule_catalog_conflict", 409
		}
		c.JSON(status, gin.H{"error": code})
		return
	}
	selection, err := checkrules.Select(checkrules.Catalog{Version: "checker-v1", Language: language, CatalogVersion: directory.CatalogVersion, Rules: directory.Rules}, input.IDs, input.Version, input.All)
	if err != nil {
		code, status := "invalid_rule_selection", 400
		if errors.Is(err, checkrules.ErrVersion) {
			code, status = "rule_catalog_version_mismatch", 409
		}
		c.JSON(status, gin.H{"error": code})
		return
	}
	request, _ = json.Marshal(struct {
		Source    string                `json:"source"`
		Selection *checkrules.Selection `json:"selection"`
	}{"manual", selection})
	run, created, err := s.enqueueRun(c, mustCurrentUser(c).ID, taskID, "source_project", projectID, kind, key, request)
	if errors.Is(err, errRunIntentConflict) {
		c.JSON(409, gin.H{"error": "run_idempotency_conflict"})
		return
	}
	if err != nil {
		c.JSON(500, gin.H{"error": "run_creation_failed"})
		return
	}
	status := 200
	if created {
		status = 201
	}
	c.JSON(status, gin.H{"run": run})
}
func equalRuleIDs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
