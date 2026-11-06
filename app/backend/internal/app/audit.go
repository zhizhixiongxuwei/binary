package app

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/gin-gonic/gin"
)

const auditExportMaxRows = 100000
const auditExportMaxBytes = 32 << 20

var auditExportSlots = make(chan struct{}, 2)

type auditFilters struct {
	Action   string
	Outcome  string
	Actor    string
	From, To *time.Time
}

func parseAuditFilters(values url.Values) (auditFilters, error) {
	var f auditFilters
	var err error
	if f.Action, err = taskListText(values.Get("action"), 96); err != nil {
		return f, err
	}
	if f.Actor, err = taskListText(values.Get("actor"), 64); err != nil {
		return f, err
	}
	f.Outcome = strings.ToLower(strings.TrimSpace(values.Get("outcome")))
	if f.Outcome == "failed" {
		f.Outcome = "failure"
	}
	if f.Outcome != "" && f.Outcome != "success" && f.Outcome != "failure" && f.Outcome != "denied" {
		return f, fmt.Errorf("invalid audit outcome")
	}
	for key, target := range map[string]**time.Time{"created_from": &f.From, "created_to": &f.To} {
		if raw := strings.TrimSpace(values.Get(key)); raw != "" {
			value, parseErr := time.Parse(time.RFC3339Nano, raw)
			if parseErr != nil {
				return f, fmt.Errorf("invalid audit timestamp")
			}
			value = value.UTC()
			*target = &value
		}
	}
	if f.From != nil && f.To != nil && f.From.After(*f.To) {
		return f, fmt.Errorf("invalid audit time range")
	}
	return f, nil
}

func (f auditFilters) conditions() (string, []any) {
	conditions := []string{"1=1"}
	args := []any{}
	if f.Action != "" {
		conditions = append(conditions, "a.action = ?")
		args = append(args, f.Action)
	}
	if f.Outcome == "failure" {
		conditions = append(conditions, "a.outcome IN ('failure', 'failed')")
	} else if f.Outcome != "" {
		conditions = append(conditions, "a.outcome = ?")
		args = append(args, f.Outcome)
	}
	if f.Actor != "" {
		// LOCATE treats % and _ literally rather than as SQL wildcard input.
		conditions = append(conditions, "(LOCATE(LOWER(?), LOWER(COALESCE(u.username, ''))) > 0 OR u.public_id = ?)")
		args = append(args, f.Actor, f.Actor)
	}
	if f.From != nil {
		conditions = append(conditions, "a.created_at >= ?")
		args = append(args, *f.From)
	}
	if f.To != nil {
		conditions = append(conditions, "a.created_at <= ?")
		args = append(args, *f.To)
	}
	return strings.Join(conditions, " AND "), args
}

const auditSelect = `SELECT a.id, u.public_id, u.username, a.action,
 a.object_type, a.object_id, a.request_id, a.client_ip, a.outcome, a.details, a.created_at
 FROM audit_logs a LEFT JOIN users u ON u.id = a.actor_user_id WHERE `

func scanAuditEntry(rows *sql.Rows) (auditEntry, error) {
	var entry auditEntry
	var actorID, actorUsername, objectType, objectID, requestID, clientIP sql.NullString
	var details []byte
	err := rows.Scan(&entry.ID, &actorID, &actorUsername, &entry.Action, &objectType, &objectID, &requestID, &clientIP, &entry.Outcome, &details, &entry.CreatedAt)
	if err != nil {
		return entry, err
	}
	entry.ActorID, entry.ActorUsername = nullableString(actorID), nullableString(actorUsername)
	entry.ObjectType, entry.ObjectID = nullableString(objectType), nullableString(objectID)
	entry.RequestID, entry.ClientIP = nullableString(requestID), nullableString(clientIP)
	if entry.Outcome == "failed" {
		entry.Outcome = "failure"
	}
	if len(details) > 0 {
		var value any
		if err := json.Unmarshal(details, &value); err != nil {
			return entry, err
		}
		entry.Details = safeAuditDetails(value)
	}
	return entry, nil
}

func safeAuditDetails(value any) any {
	switch v := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(v))
		for key, child := range v {
			normalized := strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(key))
			if strings.Contains(normalized, "token") || strings.Contains(normalized, "secret") || strings.Contains(normalized, "apikey") || strings.Contains(normalized, "passwordhash") {
				continue
			}
			switch normalized {
			case "password", "authorization", "cookie", "body", "requestbody", "responsebody", "content", "prompt":
				continue
			}
			result[key] = safeAuditDetails(child)
		}
		return result
	case []any:
		result := make([]any, len(v))
		for i, child := range v {
			result[i] = safeAuditDetails(child)
		}
		return result
	default:
		return value
	}
}

func (s *adminService) listAudit(c *gin.Context) {
	limit, beforeID, err := parseAuditPage(c.Request.URL.Query())
	filters, filterErr := parseAuditFilters(c.Request.URL.Query())
	if err != nil || filterErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_audit_query"})
		return
	}
	where, args := filters.conditions()
	if beforeID != 0 {
		where += " AND a.id < ?"
		args = append(args, beforeID)
	}
	args = append(args, limit+1)
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, auditSelect+where+" ORDER BY a.id DESC LIMIT ?", args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "audit_query_failed"})
		return
	}
	defer rows.Close()
	entries := make([]auditEntry, 0, limit+1)
	for rows.Next() {
		entry, err := scanAuditEntry(rows)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "audit_query_failed"})
			return
		}
		entries = append(entries, entry)
	}
	if rows.Err() != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "audit_query_failed"})
		return
	}
	var next any
	if len(entries) > limit {
		entries = entries[:limit]
		next = strconv.FormatUint(entries[len(entries)-1].ID, 10)
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{"entries": entries, "nextBeforeId": next})
}

var errAuditExportTooLarge = errors.New("audit export too large")

type auditExportBuffer struct {
	bytes.Buffer
	maximum int
}

func (b *auditExportBuffer) Write(value []byte) (int, error) {
	if len(value) > b.maximum-b.Len() {
		return 0, errAuditExportTooLarge
	}
	return b.Buffer.Write(value)
}

func auditCSVCell(value any) string {
	if value == nil {
		return ""
	}
	text := fmt.Sprint(value)
	// Quoting alone does not prevent spreadsheet formula evaluation. Inspect the
	// first non-whitespace character, including tabs/newlines used as prefixes.
	first := strings.TrimLeftFunc(text, unicode.IsSpace)
	if len(first) > 0 && strings.ContainsRune("=+-@", rune(first[0])) {
		return "'" + text
	}
	return text
}

func writeAuditCSV(ctx context.Context, tx *sql.Tx, filters auditFilters, maxRows, maxBytes int) ([]byte, int, uint64, error) {
	var upper uint64
	if err := tx.QueryRowContext(ctx, "SELECT COALESCE(MAX(id), 0) FROM audit_logs").Scan(&upper); err != nil {
		return nil, 0, 0, err
	}
	where, args := filters.conditions()
	where += " AND a.id <= ?"
	args = append(args, upper, maxRows+1)
	rows, err := tx.QueryContext(ctx, auditSelect+where+" ORDER BY a.id DESC LIMIT ?", args...)
	if err != nil {
		return nil, 0, upper, err
	}
	defer rows.Close()
	buffer := &auditExportBuffer{maximum: maxBytes}
	if _, err := buffer.Write([]byte{0xef, 0xbb, 0xbf}); err != nil {
		return nil, 0, upper, err
	}
	writer := csv.NewWriter(buffer)
	writer.UseCRLF = true
	if err := writer.Write([]string{"事件ID", "时间(UTC)", "操作者ID", "操作者", "操作", "对象类型", "对象ID", "请求ID", "客户端IP", "结果", "详情"}); err != nil {
		return nil, 0, upper, err
	}
	count := 0
	for rows.Next() {
		count++
		if count > maxRows {
			return nil, count, upper, errAuditExportTooLarge
		}
		entry, err := scanAuditEntry(rows)
		if err != nil {
			return nil, count, upper, err
		}
		details, err := json.Marshal(entry.Details)
		if err != nil {
			return nil, count, upper, err
		}
		cells := []any{entry.ID, entry.CreatedAt.UTC().Format(time.RFC3339Nano), entry.ActorID, entry.ActorUsername, entry.Action, entry.ObjectType, entry.ObjectID, entry.RequestID, entry.ClientIP, entry.Outcome, string(details)}
		record := make([]string, len(cells))
		for i, cell := range cells {
			record[i] = auditCSVCell(cell)
		}
		if err := writer.Write(record); err != nil {
			return nil, count, upper, err
		}
	}
	if err := rows.Err(); err != nil {
		return nil, count, upper, err
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, count, upper, err
	}
	return buffer.Bytes(), count, upper, nil
}

func (s *adminService) exportAudit(c *gin.Context) {
	filters, err := parseAuditFilters(c.Request.URL.Query())
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_audit_query"})
		return
	}
	select {
	case auditExportSlots <- struct{}{}:
		defer func() { <-auditExportSlots }()
	default:
		c.Header("Retry-After", "5")
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "audit_export_busy"})
		return
	}
	// Buffer the bounded result before writing headers: failures never deliver a
	// seemingly successful truncated CSV. Repeatable-read fixes both IDs and rows.
	ctx, cancel := context.WithTimeout(c.Request.Context(), 45*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "audit_export_failed"})
		return
	}
	defer tx.Rollback()
	body, count, upper, err := writeAuditCSV(ctx, tx, filters, auditExportMaxRows, auditExportMaxBytes)
	if errors.Is(err, errAuditExportTooLarge) {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "audit_export_too_large", "maxRows": auditExportMaxRows, "maxBytes": auditExportMaxBytes})
		return
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "audit_export_failed"})
		return
	}
	c.Set("auditExportRows", count)
	c.Set("auditExportUpperID", upper)
	c.Header("Cache-Control", "no-store")
	c.Header("Content-Disposition", `attachment; filename="audit-`+time.Now().UTC().Format("20060102-150405")+`.csv"`)
	c.Header("X-Audit-Export-Rows", strconv.Itoa(count))
	c.Header("X-Audit-Snapshot-ID", strconv.FormatUint(upper, 10))
	c.Data(http.StatusOK, "text/csv; charset=utf-8", body)
}
