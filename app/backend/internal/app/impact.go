package app

import (
	"binaryscan.local/backend/internal/disposition"
	"binaryscan.local/backend/internal/impact"
	"encoding/json"
	"github.com/gin-gonic/gin"
	"net/http"
)

func registerImpactRoutes(r *gin.RouterGroup, s *taskService, auth *authService) {
	r.POST("/tasks/:taskID/impact-analyses", auth.requireCSRF(), requireOperator(), s.queueImpact)
	r.GET("/tasks/:taskID/impact-analyses/:runID", s.getImpact)
	r.POST("/tasks/:taskID/vulnerability-occurrences/:occurrenceID/disposition", auth.requireCSRF(), requireOperator(), s.changeDisposition)
	r.GET("/tasks/:taskID/vulnerability-occurrences/:occurrenceID/history", s.dispositionHistory)
}
func (s *taskService) queueImpact(c *gin.Context) {
	if !s.scaLive(c) {
		return
	}
	var r impact.RunRequest
	if !decodeSCA(c, &r) {
		return
	}
	if r.KnowledgeDigest != "" || r.Revisions != nil {
		c.JSON(400, gin.H{"error": "server_managed_analysis_fields"})
		return
	}
	result, e := (impact.Store{DB: s.db}).Queue(c, mustCurrentUser(c).ID, c.Param("taskID"), c.GetHeader("Idempotency-Key"), r)
	if e != nil {
		s.scaError(c, e)
		return
	}
	c.JSON(202, gin.H{"run": result})
}
func (s *taskService) getImpact(c *gin.Context) {
	if !s.scaLive(c) {
		return
	}
	var status string
	var request []byte
	e := s.db.QueryRowContext(c, `SELECT status,request FROM runs WHERE id=? AND task_id=? AND kind='impact_analysis'`, c.Param("runID"), c.Param("taskID")).Scan(&status, &request)
	if e != nil {
		s.scaError(c, e)
		return
	}
	rows, e := s.db.QueryContext(c, `SELECT a.details FROM vulnerability_assessments a WHERE a.run_id=? ORDER BY a.occurrence_id LIMIT 100001`, c.Param("runID"))
	if e != nil {
		s.scaError(c, e)
		return
	}
	defer rows.Close()
	items := []json.RawMessage{}
	for rows.Next() {
		var b []byte
		if e = rows.Scan(&b); e != nil {
			s.scaError(c, e)
			return
		}
		items = append(items, json.RawMessage(b))
	}
	if e = rows.Err(); e != nil {
		s.scaError(c, e)
		return
	}
	c.JSON(200, gin.H{"status": status, "request": json.RawMessage(request), "items": items})
}
func (s *taskService) changeDisposition(c *gin.Context) {
	if !s.scaLive(c) {
		return
	}
	var request disposition.Change
	if !decodeSCA(c, &request) {
		return
	}
	result, e := (disposition.Store{DB: s.db}).Change(c, c.Param("taskID"), c.Param("occurrenceID"), c.GetHeader("Idempotency-Key"), mustCurrentUser(c).ID, request)
	if e != nil {
		switch e.Error() {
		case "invalid_disposition_request", "restore_override_expiry_required", "disposition_expiry_invalid":
			c.JSON(http.StatusBadRequest, gin.H{"error": e.Error()})
		default:
			s.scaError(c, e)
		}
		return
	}
	c.JSON(200, gin.H{"item": result})
}
func (s *taskService) dispositionHistory(c *gin.Context) {
	if !s.scaLive(c) {
		return
	}
	rows, e := s.db.QueryContext(c, `SELECT e.details,e.created_at FROM disposition_events e JOIN vulnerability_occurrences o ON o.id=e.occurrence_id WHERE o.task_id=? AND o.id=? ORDER BY e.created_at DESC,e.id DESC LIMIT 200`, c.Param("taskID"), c.Param("occurrenceID"))
	if e != nil {
		s.scaError(c, e)
		return
	}
	defer rows.Close()
	items := []gin.H{}
	for rows.Next() {
		var b []byte
		var at string
		if e = rows.Scan(&b, &at); e != nil {
			s.scaError(c, e)
			return
		}
		items = append(items, gin.H{"event": json.RawMessage(b), "createdAt": at})
	}
	if e = rows.Err(); e != nil {
		s.scaError(c, e)
		return
	}
	c.JSON(200, gin.H{"items": items})
}
