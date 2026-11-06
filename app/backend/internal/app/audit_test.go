package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestAuditFilterValidationAndCSVInjectionProtection(t *testing.T) {
	for _, query := range []url.Values{
		{"outcome": {"whatever"}}, {"created_from": {"2026-01-01"}},
		{"created_from": {"2026-01-03T00:00:00Z"}, "created_to": {"2026-01-02T00:00:00Z"}},
		{"actor": {"line\nbreak"}},
	} {
		if _, err := parseAuditFilters(query); err == nil {
			t.Fatalf("accepted invalid filter %v", query)
		}
	}
	f, err := parseAuditFilters(url.Values{"outcome": {"failed"}, "created_from": {"2026-01-01T08:00:00+08:00"}})
	if err != nil || f.Outcome != "failure" || f.From.Hour() != 0 {
		t.Fatalf("filter=%+v error=%v", f, err)
	}
	for _, text := range []string{"=1+1", "+SUM(A1)", "-1+2", "@SUM(A1)", " \t\n=1+1"} {
		if auditCSVCell(text) != "'"+text {
			t.Fatalf("unsafe CSV cell %q", text)
		}
	}
	if auditCSVCell("中文,\"说明\"") != "中文,\"说明\"" {
		t.Fatal("ordinary text changed")
	}
	safe := safeAuditDetails(map[string]any{"password": "do-not-export", "api_token": "do-not-export", "passwordReset": true, "nested": map[string]any{"prompt": "do-not-export", "reason": "safe"}})
	encoded, _ := json.Marshal(safe)
	if strings.Contains(string(encoded), "do-not-export") || !strings.Contains(string(encoded), "passwordReset") {
		t.Fatalf("unsafe details: %s", encoded)
	}
}

func auditTestRouter(t *testing.T, s *taskService) *gin.Engine {
	t.Helper()
	for _, id := range []int{1, 3} {
		token := fmt.Sprintf("audit-test-user-%d", id)
		hash := sha256.Sum256([]byte(token))
		cleanupExec(t, s, `INSERT INTO sessions (id,user_id,token_hash,csrf_token,expires_at) VALUES (?, ?, ?, 'test-csrf', DATE_ADD(UTC_TIMESTAMP(), INTERVAL 1 HOUR))`, token, id, hash[:])
	}
	auth := newAuthService(s.db)
	admin := newAdminService(s.db, auth)
	router := gin.New()
	router.Use(requestID(), requestObservability(s.db), safeRecovery())
	protected := router.Group("/api/v1")
	protected.Use(auth.authenticate())
	protected.GET("/admin/audit", requireAdministrator(), admin.listAudit)
	protected.GET("/admin/audit/export", requireAdministrator(), admin.exportAudit)
	protected.PUT("/admin/llm/settings", auth.requireCSRF(), requireAdministrator(), func(c *gin.Context) { c.Status(204) })
	return router
}

func auditRequest(router *gin.Engine, method, path, token string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(`{"password":"never-record","apiKey":"never-record","prompt":"never-record"}`))
	if token != "" {
		request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	}
	request.Header.Set("X-CSRF-Token", "test-csrf")
	writer := httptest.NewRecorder()
	router.ServeHTTP(writer, request)
	return writer
}

func TestAuditServerFiltersBeforePagingAndEnforcesAdministrator(t *testing.T) {
	s := cleanupTestService(t)
	router := auditTestRouter(t, s)
	for _, path := range []string{"/api/v1/admin/audit", "/api/v1/admin/audit/export"} {
		if w := auditRequest(router, "GET", path, ""); w.Code != 401 {
			t.Fatalf("anonymous status %d", w.Code)
		}
		if w := auditRequest(router, "GET", path, "audit-test-user-1"); w.Code != 403 {
			t.Fatalf("operator status %d", w.Code)
		}
	}
	for i := range 6 {
		actor, action, outcome := 1, "task.create", "success"
		if i%2 == 1 {
			actor, action, outcome = 3, "llm.settings.update", "failed"
		}
		cleanupExec(t, s, `INSERT INTO audit_logs(actor_user_id,action,outcome,created_at) VALUES(?,?,?,?)`, actor, action, outcome, fmt.Sprintf("2026-01-01 00:00:0%d", i))
	}
	path := "/api/v1/admin/audit?action=llm.settings.update&outcome=failure&actor=ADM&created_from=2026-01-01T00:00:01Z&created_to=2026-01-01T00:00:05Z&limit=1"
	var first struct {
		Entries []auditEntry `json:"entries"`
		Next    string       `json:"nextBeforeId"`
	}
	w := auditRequest(router, "GET", path, "audit-test-user-3")
	if err := json.Unmarshal(w.Body.Bytes(), &first); err != nil || w.Code != 200 || len(first.Entries) != 1 || first.Next == "" || first.Entries[0].Outcome != "failure" {
		t.Fatalf("page=%s err=%v", w.Body.String(), err)
	}
	// A new matching event after the first page must not duplicate or shift older IDs.
	cleanupExec(t, s, `INSERT INTO audit_logs(actor_user_id,action,outcome,created_at) VALUES(3,'llm.settings.update','failure','2026-01-01 00:00:04')`)
	var next struct {
		Entries []auditEntry `json:"entries"`
		Next    string       `json:"nextBeforeId"`
	}
	w = auditRequest(router, "GET", path+"&beforeId="+first.Next, "audit-test-user-3")
	if err := json.Unmarshal(w.Body.Bytes(), &next); err != nil || len(next.Entries) != 1 || next.Entries[0].ID >= first.Entries[0].ID {
		t.Fatalf("next=%s err=%v", w.Body.String(), err)
	}
	if w := auditRequest(router, "GET", "/api/v1/admin/audit?actor=does-not-exist", "audit-test-user-3"); !strings.Contains(w.Body.String(), `"entries":[]`) {
		t.Fatalf("actor filter ignored: %s", w.Body.String())
	}
}

func TestAuditExportIsUTF8CSVAndNeverSilentlyTruncates(t *testing.T) {
	s := cleanupTestService(t)
	router := auditTestRouter(t, s)
	cleanupExec(t, s, `INSERT INTO audit_logs(actor_user_id,action,object_type,object_id,outcome,details) VALUES(3,'report.download','report','=1+1','failed', JSON_OBJECT('name','中文说明','password','never-record'))`)
	w := auditRequest(router, "GET", "/api/v1/admin/audit/export?action=report.download&outcome=failure", "audit-test-user-3")
	if w.Code != 200 || !strings.HasPrefix(w.Body.String(), "\xef\xbb\xbf") || !strings.Contains(w.Header().Get("Content-Disposition"), ".csv") {
		t.Fatalf("export status=%d headers=%v", w.Code, w.Header())
	}
	records, err := csv.NewReader(strings.NewReader(strings.TrimPrefix(w.Body.String(), "\xef\xbb\xbf"))).ReadAll()
	if err != nil || len(records) != 2 || records[1][6] != "'=1+1" || records[1][9] != "failure" || !strings.Contains(records[1][10], "中文说明") || strings.Contains(w.Body.String(), "never-record") {
		t.Fatalf("CSV=%q error=%v", records, err)
	}
	tx, err := s.db.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	f := auditFilters{Action: "report.download"}
	if _, _, _, err := writeAuditCSV(context.Background(), tx, f, 0, auditExportMaxBytes); err != errAuditExportTooLarge {
		t.Fatalf("row bound error=%v", err)
	}
	if _, _, _, err := writeAuditCSV(context.Background(), tx, f, auditExportMaxRows, 8); err != errAuditExportTooLarge {
		t.Fatalf("byte bound error=%v", err)
	}
}

func TestRequestAuditRecordsMissingOperationsAndDeniedAttemptsWithoutBody(t *testing.T) {
	s := cleanupTestService(t)
	router := auditTestRouter(t, s)
	for _, token := range []string{"audit-test-user-3", "audit-test-user-1", ""} {
		auditRequest(router, "PUT", "/api/v1/admin/llm/settings?token=never-record", token)
	}
	rows, err := s.db.Query(`SELECT outcome,details FROM audit_logs WHERE action='llm.settings.update' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	outcomes := []string{}
	for rows.Next() {
		var outcome, details string
		if err := rows.Scan(&outcome, &details); err != nil {
			t.Fatal(err)
		}
		outcomes = append(outcomes, outcome)
		if strings.Contains(details, "never-record") {
			t.Fatal("request secrets recorded")
		}
	}
	if strings.Join(outcomes, ",") != "success,denied,denied" {
		t.Fatalf("outcomes=%v", outcomes)
	}
}

func TestHTTPAccessLoggingAndPanicRecoveryDoNotDumpCredentials(t *testing.T) {
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	defer slog.SetDefault(previous)
	router := gin.New()
	router.Use(requestID(), requestObservability(nil), safeRecovery())
	router.POST("/api/v1/probe/:id", func(c *gin.Context) { panic("never-record-panic-body") })
	request := httptest.NewRequest("POST", "/api/v1/probe/never-record-path?token=never-record-query", strings.NewReader("never-record-body"))
	request.Header.Set("Authorization", "Bearer never-record-authorization")
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "never-record-cookie"})
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != 500 || !strings.Contains(output.String(), `"status":500`) || !strings.Contains(output.String(), `"route":"/api/v1/probe/:id"`) || strings.Contains(output.String(), "never-record") {
		t.Fatalf("status=%d unsafe access output=%s", recorder.Code, output.String())
	}
}

func TestAuditExportUsesAConsistentDatabaseSnapshot(t *testing.T) {
	s := cleanupTestService(t)
	cleanupExec(t, s, `INSERT INTO audit_logs(action,outcome) VALUES('task.create','success')`)
	tx, err := s.db.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var snapshotCount int
	if err := tx.QueryRow("SELECT COUNT(*) FROM audit_logs").Scan(&snapshotCount); err != nil {
		t.Fatal(err)
	}
	cleanupExec(t, s, `INSERT INTO audit_logs(action,outcome) VALUES('task.create','success')`)
	_, count, _, err := writeAuditCSV(context.Background(), tx, auditFilters{}, auditExportMaxRows, auditExportMaxBytes)
	if err != nil || count != snapshotCount {
		t.Fatalf("export changed after snapshot: count=%d expected=%d error=%v", count, snapshotCount, err)
	}
}
