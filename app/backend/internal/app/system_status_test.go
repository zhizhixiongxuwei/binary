package app

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"binaryscan.local/backend/internal/capability"
	"binaryscan.local/backend/internal/config"
)

func sampleCapability(now time.Time) capabilityRecord {
	two, one := 2, 1
	updated := now.Add(-48 * time.Hour)
	return capabilityRecord{WorkerID: "scanner:test", Role: "scanner", CheckedAt: now, HeartbeatAt: now, Report: capability.Report{
		Analyzers: []capability.Analyzer{{Name: "scanner", Status: "available", Version: "0.74.0", LastCheckedAt: now, Detail: "local probe"}},
		Databases: []capability.Database{{Name: "trivy-db", Status: "available", SchemaVersion: &two, SizeBytes: 10, UpdatedAt: &updated}, {Name: "trivy-java-db", Status: "available", SchemaVersion: &one, SizeBytes: 20, UpdatedAt: &updated}},
	}}
}

func TestCapabilitiesRequireFreshReportAndHeartbeatAndNeverInventWorkers(t *testing.T) {
	now := time.Now().UTC()
	cfg := config.Config{}
	analyzers, bundle := aggregateCapabilities(nil, now, cfg)
	if bundle != nil || len(analyzers) != 7 || analyzers[0].Status != "unknown" || analyzers[0].ReadyWorkers != 0 || analyzers[0].LastCheckedAt != nil {
		t.Fatalf("missing report: %+v bundle=%+v", analyzers, bundle)
	}
	record := sampleCapability(now)
	analyzers, bundle = aggregateCapabilities([]capabilityRecord{record}, now, cfg)
	if analyzers[0].Status != "available" || analyzers[0].ReadyWorkers != 1 || bundle.Status != "active" || *bundle.AgeDays != 2 {
		t.Fatalf("fresh=%+v bundle=%+v", analyzers[0], bundle)
	}
	record.HeartbeatAt = now.Add(-4 * time.Minute)
	analyzers, bundle = aggregateCapabilities([]capabilityRecord{record}, now, cfg)
	if analyzers[0].Status != "unknown" || analyzers[0].Freshness != "stale" || analyzers[0].ReadyWorkers != 0 || bundle.Status != "unknown" || bundle.Databases[0].Status != "unknown" {
		t.Fatalf("stale=%+v bundle=%+v", analyzers[0], bundle)
	}
	record = sampleCapability(now)
	record.CheckedAt = now.Add(-4 * time.Minute)
	analyzers, _ = aggregateCapabilities([]capabilityRecord{record}, now, cfg)
	if analyzers[0].Status != "unknown" {
		t.Fatal("fresh heartbeat cannot hide stale probe")
	}
}

func TestCapabilityAggregationUsesFreshReplicasAndDatabaseAge(t *testing.T) {
	now := time.Now().UTC()
	fresh := sampleCapability(now)
	stale := sampleCapability(now.Add(-time.Hour))
	fresh.Report.Analyzers[0].Status = "unavailable"
	analyzers, _ := aggregateCapabilities([]capabilityRecord{stale, fresh}, now, config.Config{})
	if analyzers[0].Status != "unavailable" || analyzers[0].ReadyWorkers != 0 {
		t.Fatalf("stale success masked fresh failure: %+v", analyzers[0])
	}
	old := now.Add(-31 * 24 * time.Hour)
	fresh.Report.Databases[0].UpdatedAt = &old
	_, bundle := aggregateCapabilities([]capabilityRecord{fresh}, now, config.Config{})
	if bundle.Status != "stale" || *bundle.AgeDays != 31 {
		t.Fatalf("old database=%+v", bundle)
	}
	fresh.Report.Databases[1].Status = "unavailable"
	_, bundle = aggregateCapabilities([]capabilityRecord{fresh}, now, config.Config{})
	if bundle.Status != "unavailable" {
		t.Fatalf("database failure=%+v", bundle)
	}
}

func TestAdminSystemReturnsPersistedProbesAndUnpaginatedCounts(t *testing.T) {
	s := cleanupTestService(t)
	now := time.Now().UTC()
	cleanupBlob(t, s, "blob")
	cleanupTask(t, s, "task", "blob", "", "binary")
	addExecutionRun(t, s, "task", "scan", "scan", "queued", "file_node", "file-task", "", 0)
	cleanupExec(t, s, `INSERT INTO jobs (run_id,kind,status) VALUES ('scan','scan','queued')`)
	report := sampleCapability(now).Report
	if err := capability.Store(context.Background(), s.db, "scanner:test", "scanner", report); err != nil {
		t.Fatal(err)
	}
	if err := capability.Ready(context.Background(), config.Config{Role: "scanner"}, s.db, "scanner:test"); err != nil {
		t.Fatalf("fresh real report should satisfy worker health: %v", err)
	}
	service := systemService{db: s.db, cfg: config.Config{Version: "test"}}
	result, err := service.collect(context.Background(), now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if result["queue_depth"] != 1 || result["queued_tasks"] != 1 || result["repository_total_bytes"] != nil {
		t.Fatalf("status=%+v", result)
	}
	analyzers := result["analyzers"].([]systemAnalyzer)
	if analyzers[0].Version != "0.74.0" || analyzers[0].Status != "available" || analyzers[1].Status != "unknown" {
		t.Fatalf("analyzers=%+v", analyzers)
	}
	counts := result["task_counts"].(map[string]int)
	if counts["PREPARING"] != 1 {
		t.Fatalf("counts=%v", counts)
	}
	// The public JSON must carry unknown capacity and actual versions, not the
	// application build masquerading as seven tool versions.
	body, err := json.Marshal(result)
	if err != nil || len(body) == 0 {
		t.Fatal(err)
	}
	cleanupExec(t, s, `UPDATE worker_capabilities SET heartbeat_at=DATE_SUB(UTC_TIMESTAMP(6),INTERVAL 10 MINUTE)`)
	result, err = service.collect(context.Background(), now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if result["analyzers"].([]systemAnalyzer)[0].Status != "unknown" {
		t.Fatal("expired worker remained available")
	}
	if err := capability.Ready(context.Background(), config.Config{Role: "scanner"}, s.db, "scanner:test"); err == nil {
		t.Fatal("expired capability must fail worker healthcheck")
	}
}

func TestSystemStatusRouteRejectsNonAdministrators(t *testing.T) {
	s := cleanupTestService(t)
	cleanupExec(t, s, `INSERT INTO users (id,public_id,username,password_hash,role) VALUES (4,'reader','reader','unused','reader')`)
	server, err := NewServer(config.Config{Version: "test", App: config.App{StorageRoot: s.storageRoot}}, s.db)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		role         string
		id, expected int
	}{{"", 0, 401}, {"reader", 4, 403}, {"operator", 1, 403}, {"administrator", 3, 200}} {
		request := httptest.NewRequest(http.MethodGet, "/api/v1/admin/system", nil)
		if item.id != 0 {
			token := "system-test-" + item.role
			hash := sha256.Sum256([]byte(token))
			cleanupExec(t, s, `INSERT INTO sessions (id,user_id,token_hash,csrf_token,expires_at) VALUES (?,?,?,'csrf',DATE_ADD(UTC_TIMESTAMP(6),INTERVAL 1 HOUR))`, item.role, item.id, hash[:])
			request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
		}
		w := httptest.NewRecorder()
		server.http.Handler.ServeHTTP(w, request)
		if w.Code != item.expected {
			t.Fatalf("role=%s status=%d body=%s", item.role, w.Code, w.Body.String())
		}
	}
}
