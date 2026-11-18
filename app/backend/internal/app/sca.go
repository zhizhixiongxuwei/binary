package app

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"binaryscan.local/backend/internal/filetype"
	"binaryscan.local/backend/internal/impact"
	"binaryscan.local/backend/internal/job"
	"binaryscan.local/backend/internal/sca"
	"github.com/gin-gonic/gin"
)

func sameJSONIntent(a, b []byte) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	a, _ = json.Marshal(x)
	b, _ = json.Marshal(y)
	return bytes.Equal(a, b)
}
func registerSCARoutes(r *gin.RouterGroup, s *taskService, auth *authService) {
	r.GET("/analysis-capabilities", s.scaCapabilities)
	r.GET("/tasks/:taskID/inventories", s.scaInventories)
	r.GET("/tasks/:taskID/inventories/:inventoryID/components", s.scaComponents)
	r.GET("/tasks/:taskID/inventories/:inventoryID/dependencies", s.scaDependencies)
	r.GET("/tasks/:taskID/vulnerability-occurrences", s.scaOccurrences)
	r.GET("/tasks/:taskID/vulnerability-occurrences/:occurrenceID", s.scaOccurrence)
	r.POST("/tasks/:taskID/sca-scans", auth.requireCSRF(), requireOperator(), s.queueSCAScan)
	r.POST("/tasks/:taskID/sbom-links", auth.requireCSRF(), requireOperator(), s.scaLink)
	r.POST("/tasks/:taskID/swid-collections", auth.requireCSRF(), requireOperator(), s.swidCollection)
	r.GET("/environment-profiles", s.scaEnvironments)
	r.GET("/environment-profiles/:profileID", s.scaEnvironment)
	r.POST("/environment-profiles", auth.requireCSRF(), requireOperator(), s.scaSaveEnvironment)
	r.PATCH("/environment-profiles/:profileID", auth.requireCSRF(), requireOperator(), s.scaSaveEnvironment)
	r.GET("/tasks/:taskID/analysis-policies", s.scaPolicies)
	r.POST("/tasks/:taskID/analysis-policies", auth.requireCSRF(), requireOperator(), s.scaSavePolicy)
}
func (s *taskService) scaError(c *gin.Context, err error) {
	slog.Error("sca request failed", "error", err, "request_id", c.GetString("requestID"))
	if errors.Is(err, sql.ErrNoRows) || err.Error() == "task_not_found" {
		c.JSON(404, gin.H{"error": "sca_object_not_found"})
		return
	}
	if strings.Contains(err.Error(), "conflict") {
		c.JSON(409, gin.H{"error": err.Error()})
		return
	}
	c.JSON(500, gin.H{"error": "sca_request_failed"})
}
func (s *taskService) scaLive(c *gin.Context) bool {
	if err := sca.TaskLive(c, s.db, c.Param("taskID")); err != nil {
		s.scaError(c, err)
		return false
	}
	return true
}
func decodeSCA(c *gin.Context, v any) bool {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 1<<20)
	d := json.NewDecoder(c.Request.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil || d.Decode(&struct{}{}) != io.EOF {
		c.JSON(400, gin.H{"error": "invalid_sca_request"})
		return false
	}
	return true
}
func (s *taskService) scaCapabilities(c *gin.Context) {
	b, e := impact.Rules()
	if e != nil {
		s.scaError(c, e)
		return
	}
	c.JSON(200, gin.H{"schemaVersion": sca.Version, "formats": []gin.H{{"format": "spdx-json", "versions": []string{"SPDX-2.3"}}, {"format": "spdx-tag-value", "versions": []string{"SPDX-2.3"}}, {"format": "cyclonedx-json", "versions": []string{"1.4", "1.5", "1.6"}}, {"format": "cyclonedx-xml", "versions": []string{"1.4", "1.5", "1.6"}}, {"format": "swid-xml", "versions": []string{"2015"}}}, "javaFormats": []string{"jar", "war"}, "javaReleases": []int{8, 11, 17, 21}, "rules": b, "runtimeVerification": "See worker capability reports; installed protocol support is not an end-to-end sample verdict"})
}
func (s *taskService) scaInventories(c *gin.Context) {
	if !s.scaLive(c) {
		return
	}
	items, e := (sca.Store{DB: s.db}).Inventories(c, c.Param("taskID"))
	if e != nil {
		s.scaError(c, e)
		return
	}
	for i := range items {
		items[i].Document.Components = nil
		items[i].Document.Dependencies = nil
	}
	rows, e := s.db.QueryContext(c, `SELECT id,kind,status,COALESCE(result_quality,''),COALESCE(error_message,''),COALESCE(JSON_UNQUOTE(JSON_EXTRACT(request,'$.inventoryId')),'') FROM runs WHERE task_id=? AND kind IN ('sbom_parse','sca_scan','impact_analysis') ORDER BY created_at DESC,id DESC LIMIT 100`, c.Param("taskID"))
	if e != nil {
		s.scaError(c, e)
		return
	}
	defer rows.Close()
	runs := []gin.H{}
	for rows.Next() {
		var id, kind, status, quality, message, inventory string
		if e = rows.Scan(&id, &kind, &status, &quality, &message, &inventory); e != nil {
			s.scaError(c, e)
			return
		}
		runs = append(runs, gin.H{"id": id, "kind": kind, "status": status, "quality": quality, "error": message, "inventoryId": inventory})
	}
	if e = rows.Err(); e != nil {
		s.scaError(c, e)
		return
	}
	c.JSON(200, gin.H{"items": items, "runs": runs})
}
func (s *taskService) scaComponents(c *gin.Context) {
	if !s.scaLive(c) {
		return
	}
	v, e := (sca.Store{DB: s.db}).Inventory(c, c.Param("taskID"), c.Param("inventoryID"))
	if e != nil {
		s.scaError(c, e)
		return
	}
	start, _ := strconv.Atoi(c.Query("offset"))
	if start < 0 || start > len(v.Document.Components) {
		c.JSON(400, gin.H{"error": "invalid_offset"})
		return
	}
	end := start + 100
	if end > len(v.Document.Components) {
		end = len(v.Document.Components)
	}
	c.JSON(200, gin.H{"items": v.Document.Components[start:end], "total": len(v.Document.Components), "nextOffset": end, "hasMore": end < len(v.Document.Components)})
}
func (s *taskService) scaDependencies(c *gin.Context) {
	if !s.scaLive(c) {
		return
	}
	v, e := (sca.Store{DB: s.db}).Inventory(c, c.Param("taskID"), c.Param("inventoryID"))
	if e != nil {
		s.scaError(c, e)
		return
	}
	start, _ := strconv.Atoi(c.Query("offset"))
	if start < 0 || start > len(v.Document.Dependencies) {
		c.JSON(400, gin.H{"error": "invalid_offset"})
		return
	}
	end := start + 200
	if end > len(v.Document.Dependencies) {
		end = len(v.Document.Dependencies)
	}
	c.JSON(200, gin.H{"items": v.Document.Dependencies[start:end], "total": len(v.Document.Dependencies), "hasMore": end < len(v.Document.Dependencies), "nextOffset": end})
}
func (s *taskService) scaOccurrences(c *gin.Context) {
	if !s.scaLive(c) {
		return
	}
	items, e := (sca.Store{DB: s.db}).Occurrences(c, c.Param("taskID"), c.Query("cursor"), 101, sca.Filter{Status: c.Query("status"), Severity: c.Query("severity"), Reachability: c.Query("reachability"), Environment: c.Query("environment"), Attack: c.Query("attack"), Source: c.Query("source"), ProfileID: c.Query("environmentProfileId")})
	if e != nil {
		s.scaError(c, e)
		return
	}
	more := len(items) > 100
	if more {
		items = items[:100]
	}
	cursor := ""
	if more {
		cursor = items[len(items)-1].ID
	}
	summary, e := (sca.Store{DB: s.db}).Summary(c, c.Param("taskID"))
	if e != nil {
		s.scaError(c, e)
		return
	}
	c.JSON(200, gin.H{"items": items, "hasMore": more, "nextCursor": cursor, "summary": summary})
}
func (s *taskService) scaOccurrence(c *gin.Context) {
	if !s.scaLive(c) {
		return
	}
	id := c.Param("occurrenceID")
	if len(id) != 64 {
		c.JSON(400, gin.H{"error": "invalid_occurrence_id"})
		return
	}
	items, e := (sca.Store{DB: s.db}).Occurrences(c, c.Param("taskID"), "", 1, sca.Filter{ID: id})
	if e != nil {
		s.scaError(c, e)
		return
	}
	for _, v := range items {
		if v.ID == id {
			c.JSON(200, gin.H{"item": v})
			return
		}
	}
	c.JSON(404, gin.H{"error": "sca_object_not_found"})
}
func (s *taskService) queueSCAScan(c *gin.Context) {
	if !s.scaLive(c) {
		return
	}
	var mode, format, fileID string
	e := s.db.QueryRowContext(c, `SELECT COALESCE(t.analysis_mode,''),f.detected_format,f.id FROM tasks t JOIN file_nodes f ON f.task_id=t.id AND f.parent_id IS NULL WHERE t.id=? LIMIT 1`, c.Param("taskID")).Scan(&mode, &format, &fileID)
	if e != nil {
		s.scaError(c, e)
		return
	}
	m := filetype.AnalysisMode(mode)
	if !filetype.SupportsAnalysisMode(format, m) || (m != filetype.AnalysisModeSBOM && m != filetype.AnalysisModeJavaSCA) {
		c.JSON(400, gin.H{"error": "sca_mode_not_applicable"})
		return
	}
	kind := job.KindSCAScan
	if m == filetype.AnalysisModeSBOM {
		kind = job.KindSBOMParse
	}
	s.queueManualRun(c, c.Param("taskID"), "file_node", fileID, kind)
}
func (s *taskService) scaEnvironments(c *gin.Context) {
	v, e := (impact.Store{DB: s.db}).Environments(c)
	if e != nil {
		s.scaError(c, e)
		return
	}
	c.JSON(200, gin.H{"items": v})
}
func (s *taskService) scaEnvironment(c *gin.Context) {
	var id string
	e := s.db.QueryRowContext(c, `SELECT v.id FROM environment_versions v JOIN environment_profiles p ON p.id=v.profile_id AND p.revision=v.revision WHERE p.id=?`, c.Param("profileID")).Scan(&id)
	if e != nil {
		s.scaError(c, e)
		return
	}
	v, e := (impact.Store{DB: s.db}).Environment(c, id)
	if e != nil {
		s.scaError(c, e)
		return
	}
	c.JSON(200, gin.H{"item": v})
}
func (s *taskService) scaSaveEnvironment(c *gin.Context) {
	var request struct {
		ExpectedRevision uint64             `json:"expectedRevision"`
		Config           impact.Environment `json:"config"`
	}
	if !decodeSCA(c, &request) {
		return
	}
	if e := request.Config.Validate(); e != nil {
		c.JSON(400, gin.H{"error": e.Error()})
		return
	}
	v, e := (impact.Store{DB: s.db}).SaveEnvironment(c, mustCurrentUser(c).ID, c.Param("profileID"), request.ExpectedRevision, request.Config)
	if e != nil {
		s.scaError(c, e)
		return
	}
	c.JSON(201, gin.H{"item": v})
}
func (s *taskService) scaPolicies(c *gin.Context) {
	if !s.scaLive(c) {
		return
	}
	v, e := (impact.Store{DB: s.db}).Policies(c, c.Param("taskID"))
	if e != nil {
		s.scaError(c, e)
		return
	}
	c.JSON(200, gin.H{"items": v})
}
func (s *taskService) scaSavePolicy(c *gin.Context) {
	if !s.scaLive(c) {
		return
	}
	var p impact.Policy
	if !decodeSCA(c, &p) {
		return
	}
	if e := p.Validate(); e != nil {
		c.JSON(400, gin.H{"error": e.Error()})
		return
	}
	v, e := (impact.Store{DB: s.db}).SavePolicy(c, mustCurrentUser(c).ID, c.Param("taskID"), p)
	if e != nil {
		s.scaError(c, e)
		return
	}
	c.JSON(201, gin.H{"item": v})
}
func (s *taskService) scaLink(c *gin.Context) {
	if !s.scaLive(c) {
		return
	}
	var r struct {
		SBOMTaskID string `json:"sbomTaskId"`
	}
	if !decodeSCA(c, &r) {
		return
	}
	if e := sca.TaskLive(c, s.db, r.SBOMTaskID); e != nil {
		s.scaError(c, e)
		return
	}
	a, e := (sca.Store{DB: s.db}).Inventories(c, c.Param("taskID"))
	if e != nil {
		s.scaError(c, e)
		return
	}
	b, e := (sca.Store{DB: s.db}).Inventories(c, r.SBOMTaskID)
	if e != nil {
		s.scaError(c, e)
		return
	}
	if len(a) == 0 || len(b) == 0 {
		c.JSON(409, gin.H{"error": "inventory_required"})
		return
	}
	fullA, e := (sca.Store{DB: s.db}).Inventory(c, c.Param("taskID"), a[0].ID)
	if e != nil {
		s.scaError(c, e)
		return
	}
	fullB, e := (sca.Store{DB: s.db}).Inventory(c, r.SBOMTaskID, b[0].ID)
	if e != nil {
		s.scaError(c, e)
		return
	}
	a[0] = fullA
	b[0] = fullB
	matches := []string{}
	missing := []string{}
	for _, sc := range b[0].Document.Components {
		found := false
		for _, jc := range a[0].Document.Components {
			if sc.PURL != "" && sc.PURL == jc.PURL {
				found = true
				matches = append(matches, sc.PURL)
			}
		}
		if !found {
			missing = append(missing, sc.SourceRef)
		}
	}
	result := gin.H{"status": "identity_comparison_only", "artifactBindingVerified": false, "matchedPurls": matches, "unmatchedRefs": missing, "sbomFingerprint": b[0].Document.Fingerprint, "javaFingerprint": a[0].Document.Fingerprint}
	body, _ := json.Marshal(result)
	_, e = s.db.ExecContext(c, `INSERT INTO sca_sbom_links(task_id,sbom_task_id,verification) VALUES(?,?,?) ON DUPLICATE KEY UPDATE verification=VALUES(verification)`, c.Param("taskID"), r.SBOMTaskID, body)
	if e != nil {
		s.scaError(c, e)
		return
	}
	c.JSON(200, result)
}
