package capability

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"binaryscan.local/backend/internal/checkrules"
	"binaryscan.local/backend/internal/config"
)

type Analyzer struct {
	Name            string    `json:"name"`
	Version         string    `json:"version"`
	ExpectedVersion string    `json:"expected_version"`
	Status          string    `json:"status"`
	Scope           string    `json:"scope"`
	Detail          string    `json:"detail"`
	RuntimeName     string    `json:"runtime_name"`
	RuntimeVersion  string    `json:"runtime_version"`
	Verification    string    `json:"verification"`
	LastCheckedAt   time.Time `json:"last_checked_at"`
}

type Database struct {
	Name          string     `json:"name"`
	Status        string     `json:"status"`
	Path          string     `json:"path"`
	SchemaVersion *int       `json:"schema_version"`
	SizeBytes     int64      `json:"size_bytes"`
	UpdatedAt     *time.Time `json:"updated_at"`
	NextUpdate    *time.Time `json:"next_update"`
	DownloadedAt  *time.Time `json:"downloaded_at"`
	Error         string     `json:"error"`
}

type Report struct {
	Analyzers    []Analyzer               `json:"analyzers"`
	Databases    []Database               `json:"databases"`
	RuleCatalogs []checkrules.Observation `json:"rule_catalogs,omitempty"`
}

func ProbeInterval(cfg config.Config) time.Duration {
	if cfg.Worker.CapabilityProbeInterval <= 0 {
		return time.Minute
	}
	return cfg.Worker.CapabilityProbeInterval
}

func ReportTTL(cfg config.Config) time.Duration {
	if cfg.Worker.CapabilityReportTTL <= 0 {
		return 3 * time.Minute
	}
	return cfg.Worker.CapabilityReportTTL
}

func StaleDays(cfg config.Config) int {
	if cfg.Worker.DatabaseStaleDays <= 0 {
		return 30
	}
	return cfg.Worker.DatabaseStaleDays
}

// ReportLoop is independent of job execution, so a long analysis cannot stop
// capability heartbeats. Reports are local probes, never synthetic scan results.
func ReportLoop(ctx context.Context, cfg config.Config, db *sql.DB, workerID string) {
	probe := time.NewTicker(ProbeInterval(cfg))
	defer probe.Stop()
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	publish := func() {
		report := Collect(ctx, cfg)
		if err := Store(ctx, db, workerID, cfg.Role, report); err != nil && ctx.Err() == nil {
			slog.Warn("capability report publication failed", "role", cfg.Role)
		}
	}
	publish()
	for {
		select {
		case <-ctx.Done():
			return
		case <-probe.C:
			publish()
		case <-heartbeat.C:
			_, err := db.ExecContext(ctx, `UPDATE worker_capabilities SET heartbeat_at=UTC_TIMESTAMP(6) WHERE worker_id=?`, workerID)
			if err != nil && ctx.Err() == nil {
				slog.Warn("capability heartbeat failed", "role", cfg.Role)
			}
		}
	}
}

func Store(ctx context.Context, db *sql.DB, workerID, role string, report Report) error {
	body, err := json.Marshal(report)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `INSERT INTO worker_capabilities (worker_id,role,report,checked_at,heartbeat_at)
	 VALUES (?,?,?,UTC_TIMESTAMP(6),UTC_TIMESTAMP(6)) ON DUPLICATE KEY UPDATE role=VALUES(role),report=VALUES(report),
	 checked_at=VALUES(checked_at),heartbeat_at=VALUES(heartbeat_at)`, workerID, role, body)
	return err
}

// Ready consumes the cached report; Docker healthchecks never spawn expensive
// tools or claim input jobs. Missing or expired evidence cannot be healthy.
func Ready(ctx context.Context, cfg config.Config, db *sql.DB, workerID string) error {
	var body []byte
	var checked, heartbeat time.Time
	if err := db.QueryRowContext(ctx, `SELECT report,checked_at,heartbeat_at FROM worker_capabilities WHERE worker_id=? AND role=?`, workerID, cfg.Role).Scan(&body, &checked, &heartbeat); err != nil {
		return fmt.Errorf("capability report unavailable")
	}
	now := time.Now().UTC()
	ttl := ReportTTL(cfg)
	if checked.Before(now.Add(-ttl)) || heartbeat.Before(now.Add(-ttl)) || checked.After(now.Add(5*time.Minute)) || heartbeat.After(now.Add(5*time.Minute)) {
		return fmt.Errorf("capability report expired")
	}
	var report Report
	if json.Unmarshal(body, &report) != nil || len(report.Analyzers) == 0 {
		return fmt.Errorf("capability report invalid")
	}
	for _, analyzer := range report.Analyzers {
		if analyzer.Status != "available" {
			return fmt.Errorf("capability %s is not available", analyzer.Name)
		}
	}
	return nil
}
