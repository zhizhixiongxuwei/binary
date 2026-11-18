package app

import (
	"binaryscan.local/backend/internal/job"
	"binaryscan.local/backend/internal/sbom"
	"binaryscan.local/backend/internal/sca"
	"encoding/json"
	"github.com/gin-gonic/gin"
	"strings"
)

func (s *taskService) swidCollection(c *gin.Context) {
	if !s.scaLive(c) {
		return
	}
	var file, format, mode string
	if e := s.db.QueryRowContext(c, `SELECT f.id,f.detected_format,t.analysis_mode FROM tasks t JOIN file_nodes f ON f.task_id=t.id AND f.parent_id IS NULL WHERE t.id=? LIMIT 1`, c.Param("taskID")).Scan(&file, &format, &mode); e != nil {
		s.scaError(c, e)
		return
	}
	if mode != "sbom" || format != "swid-xml" {
		c.JSON(400, gin.H{"error": "swid_task_required"})
		return
	}
	var request sbom.CollectionRequest
	if !decodeSCA(c, &request) {
		return
	}
	if len(request.Members) < 1 || len(request.Members) > 100 {
		c.JSON(400, gin.H{"error": "swid_collection_limit"})
		return
	}
	tags := []sbom.LocalTag{}
	for _, member := range request.Members {
		if e := sca.TaskLive(c, s.db, member.TaskID); e != nil {
			s.scaError(c, e)
			return
		}
		inv, e := (sca.Store{DB: s.db}).Inventory(c, member.TaskID, member.InventoryID)
		if e != nil {
			s.scaError(c, e)
			return
		}
		if inv.Document.Fingerprint != member.Fingerprint {
			c.JSON(409, gin.H{"error": "swid_collection_snapshot_conflict"})
			return
		}
		tags = append(tags, sbom.LocalTag{Document: inv.Document, LogicalPath: member.LogicalPath})
	}
	if _, e := sbom.SWIDCollection(tags, request.IdentityMappings); e != nil {
		c.JSON(400, gin.H{"error": e.Error()})
		return
	}
	key := strings.TrimSpace(c.GetHeader("Idempotency-Key"))
	if key == "" || len(key) > 128 {
		c.JSON(400, gin.H{"error": "idempotency_key_required"})
		return
	}
	body, _ := json.Marshal(request)
	run, _, e := s.enqueueRun(c, mustCurrentUser(c).ID, c.Param("taskID"), "file_node", file, job.KindSBOMParse, key, body)
	if e != nil {
		s.scaError(c, e)
		return
	}
	c.JSON(202, gin.H{"run": run})
}
