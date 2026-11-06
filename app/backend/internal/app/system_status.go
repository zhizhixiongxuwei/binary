package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"binaryscan.local/backend/internal/capability"
	"binaryscan.local/backend/internal/config"

	"github.com/gin-gonic/gin"
)

type systemService struct {
	db  *sql.DB
	cfg config.Config
}

type systemAnalyzer struct {
	Name                string     `json:"name"`
	Version             string     `json:"version"`
	ExpectedVersion     string     `json:"expected_version"`
	Status              string     `json:"status"`
	Freshness           string     `json:"freshness"`
	Scope               string     `json:"scope"`
	Detail              string     `json:"detail"`
	RuntimeName         string     `json:"runtime_name"`
	RuntimeVersion      string     `json:"runtime_version"`
	Verification        string     `json:"verification"`
	RequiredWorkerKinds []string   `json:"required_worker_kinds"`
	ReadyWorkerKinds    []string   `json:"ready_worker_kinds"`
	ReadyWorkers        int        `json:"ready_workers"`
	LastCheckedAt       *time.Time `json:"last_checked_at"`
	LastRunAt           *time.Time `json:"last_run_at"`
}

type systemBundle struct {
	Version            string                `json:"version"`
	Status             string                `json:"status"`
	Freshness          string                `json:"freshness"`
	TrivyDBVersion     string                `json:"trivy_db_version"`
	TrivyJavaDBVersion string                `json:"trivy_java_db_version"`
	RegisteredAt       time.Time             `json:"registered_at"`
	LastCheckedAt      time.Time             `json:"last_checked_at"`
	AgeDays            *int                  `json:"age_days"`
	StaleAfterDays     int                   `json:"stale_after_days"`
	Databases          []capability.Database `json:"databases"`
}

type capabilityRecord struct {
	WorkerID, Role         string
	CheckedAt, HeartbeatAt time.Time
	Report                 capability.Report
}

var analyzerRoles = []struct {
	Name, Role, Scope string
	Kinds             []string
}{
	{"scanner", "scanner", "归档解析、容器漏洞检测", []string{"scan", "archive_import", "trivy_scan"}},
	{"native-decompiler", "native-decompiler", "原生二进制反编译", []string{"native_decompile"}},
	{"jvm-decompiler", "jvm-decompiler", "Java / Android 反编译", []string{"jvm_decompile"}},
	{"pyc-decompiler", "pyc-decompiler", "Python 字节码反编译", []string{"pyc_decompile"}},
	{"c-checker", "scanner", "C 源码检测", []string{"c_check"}},
	{"java-checker", "scanner", "Java 源码检测", []string{"java_check"}},
	{"python-checker", "scanner", "Python 源码检测", []string{"python_check"}},
}

func (s *systemService) status(c *gin.Context) {
	result, err := s.collect(c.Request.Context(), time.Now().UTC())
	if err != nil {
		_ = c.Error(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "system_status_query_failed"})
		return
	}
	c.JSON(http.StatusOK, result)
}

func reportFresh(record capabilityRecord, now time.Time, ttl time.Duration) bool {
	return !record.CheckedAt.Before(now.Add(-ttl)) && !record.HeartbeatAt.Before(now.Add(-ttl)) && !record.CheckedAt.After(now.Add(5*time.Minute)) && !record.HeartbeatAt.After(now.Add(5*time.Minute))
}

func aggregateCapabilities(records []capabilityRecord, now time.Time, cfg config.Config) ([]systemAnalyzer, *systemBundle) {
	result := make([]systemAnalyzer, 0, len(analyzerRoles))
	for _, definition := range analyzerRoles {
		a := systemAnalyzer{Name: definition.Name, Status: "unknown", Freshness: "missing", Scope: definition.Scope, Verification: "probe", Detail: "尚无 Worker 本地探测报告", RequiredWorkerKinds: []string{definition.Role}, ReadyWorkerKinds: []string{}}
		var best *capability.Analyzer
		var bestRecord *capabilityRecord
		for i := range records {
			record := &records[i]
			if record.Role != definition.Role {
				continue
			}
			for j := range record.Report.Analyzers {
				candidate := &record.Report.Analyzers[j]
				if candidate.Name != definition.Name {
					continue
				}
				fresh := reportFresh(*record, now, capability.ReportTTL(cfg))
				if fresh && candidate.Status == "available" {
					a.ReadyWorkers++
				}
				if bestRecord == nil || (fresh && !reportFresh(*bestRecord, now, capability.ReportTTL(cfg))) ||
					(fresh == reportFresh(*bestRecord, now, capability.ReportTTL(cfg)) && ((candidate.Status == "available" && best.Status != "available") || ((candidate.Status == "available") == (best.Status == "available") && record.CheckedAt.After(bestRecord.CheckedAt)))) {
					best, bestRecord = candidate, record
				}
			}
		}
		if bestRecord != nil {
			a.Version, a.ExpectedVersion, a.RuntimeName, a.RuntimeVersion = best.Version, best.ExpectedVersion, best.RuntimeName, best.RuntimeVersion
			a.LastCheckedAt = &bestRecord.CheckedAt
			if reportFresh(*bestRecord, now, capability.ReportTTL(cfg)) {
				a.Status, a.Freshness, a.Detail = best.Status, "fresh", best.Detail
			} else {
				a.Freshness = "stale"
				a.Detail = "Worker 本地探测报告已过期，当前可用性未知"
			}
			if a.ReadyWorkers > 0 {
				a.Status = "available"
				a.ReadyWorkerKinds = []string{definition.Role}
			}
		}
		result = append(result, a)
	}
	var scanner *capabilityRecord
	for i := range records {
		record := &records[i]
		if record.Role != "scanner" || len(record.Report.Databases) == 0 {
			continue
		}
		if scanner == nil || (reportFresh(*record, now, capability.ReportTTL(cfg)) && !reportFresh(*scanner, now, capability.ReportTTL(cfg))) ||
			(reportFresh(*record, now, capability.ReportTTL(cfg)) == reportFresh(*scanner, now, capability.ReportTTL(cfg)) && record.CheckedAt.After(scanner.CheckedAt)) {
			scanner = record
		}
	}
	if scanner == nil {
		return result, nil
	}
	bundle := &systemBundle{Status: "active", Freshness: "fresh", RegisteredAt: scanner.CheckedAt, LastCheckedAt: scanner.CheckedAt, StaleAfterDays: capability.StaleDays(cfg), Databases: append([]capability.Database{}, scanner.Report.Databases...)}
	var oldest *time.Time
	for i := range bundle.Databases {
		database := &bundle.Databases[i]
		if database.SchemaVersion != nil {
			if database.Name == "trivy-db" {
				bundle.TrivyDBVersion = strconv.Itoa(*database.SchemaVersion)
			}
			if database.Name == "trivy-java-db" {
				bundle.TrivyJavaDBVersion = strconv.Itoa(*database.SchemaVersion)
			}
		}
		if database.Status != "available" {
			bundle.Status = "unavailable"
		}
		if database.UpdatedAt != nil && (oldest == nil || database.UpdatedAt.Before(*oldest)) {
			oldest = database.UpdatedAt
		}
		if !reportFresh(*scanner, now, capability.ReportTTL(cfg)) {
			database.Status = "unknown"
			database.Error = "探测报告已过期，需等待 Worker 更新"
		}
	}
	bundle.Version = "schema " + bundle.TrivyDBVersion + " / " + bundle.TrivyJavaDBVersion
	if oldest != nil {
		age := int(now.Sub(*oldest).Hours() / 24)
		if age < 0 {
			age = 0
		}
		bundle.AgeDays = &age
		if age > bundle.StaleAfterDays && bundle.Status == "active" {
			bundle.Status = "stale"
		}
	}
	if len(bundle.Databases) != 2 {
		bundle.Status = "unavailable"
	}
	if !reportFresh(*scanner, now, capability.ReportTTL(cfg)) {
		bundle.Status = "unknown"
		bundle.Freshness = "stale"
	}
	return result, bundle
}

func (s *systemService) collect(ctx context.Context, now time.Time) (gin.H, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT worker_id,role,report,checked_at,heartbeat_at FROM worker_capabilities ORDER BY checked_at DESC LIMIT 1000`)
	if err != nil {
		return nil, err
	}
	records := []capabilityRecord{}
	for rows.Next() {
		var record capabilityRecord
		var body []byte
		if err := rows.Scan(&record.WorkerID, &record.Role, &body, &record.CheckedAt, &record.HeartbeatAt); err != nil {
			rows.Close()
			return nil, err
		}
		if json.Unmarshal(body, &record.Report) == nil {
			records = append(records, record)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	analyzers, bundle := aggregateCapabilities(records, now, s.cfg)
	rows, err = tx.QueryContext(ctx, `SELECT kind,MAX(completed_at) FROM runs WHERE completed_at IS NOT NULL GROUP BY kind`)
	if err != nil {
		return nil, err
	}
	lastRuns := map[string]time.Time{}
	for rows.Next() {
		var kind string
		var completed time.Time
		if err := rows.Scan(&kind, &completed); err != nil {
			rows.Close()
			return nil, err
		}
		lastRuns[kind] = completed
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for i, definition := range analyzerRoles {
		for _, kind := range definition.Kinds {
			if completed, ok := lastRuns[kind]; ok && (analyzers[i].LastRunAt == nil || completed.After(*analyzers[i].LastRunAt)) {
				value := completed
				analyzers[i].LastRunAt = &value
			}
		}
	}
	counts := map[string]int{}
	rows, err = tx.QueryContext(ctx, `SELECT `+taskExecutionStatusSQL("t")+` AS execution_status,COUNT(*) FROM tasks t WHERE t.deleted_at IS NULL AND COALESCE(t.analysis_mode,t.input_category,'binary')<>'archive' GROUP BY execution_status`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			rows.Close()
			return nil, err
		}
		counts[status] = count
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	var queuedTasks, activeTasks, queueDepth, observedLeases, observedOwners int
	var oldestHeartbeat, latestHeartbeat sql.NullTime
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(DISTINCT CASE WHEN j.status='queued' THEN r.task_id END),
	 COUNT(DISTINCT CASE WHEN j.status IN ('leased','running') THEN r.task_id END),COALESCE(SUM(j.status='queued'),0),
	 COALESCE(SUM(j.status IN ('leased','running')),0),COUNT(DISTINCT CASE WHEN j.status IN ('leased','running') THEN j.lease_owner END),
	 MIN(CASE WHEN j.status IN ('leased','running') THEN j.heartbeat_at END),MAX(CASE WHEN j.status IN ('leased','running') THEN j.heartbeat_at END)
	 FROM jobs j JOIN runs r ON r.id=j.run_id JOIN tasks t ON t.id=r.task_id AND t.deleted_at IS NULL`).Scan(&queuedTasks, &activeTasks, &queueDepth, &observedLeases, &observedOwners, &oldestHeartbeat, &latestHeartbeat); err != nil {
		return nil, err
	}
	leasesByKind := map[string]int{}
	rows, err = tx.QueryContext(ctx, `SELECT j.kind,COUNT(*) FROM jobs j JOIN runs r ON r.id=j.run_id JOIN tasks t ON t.id=r.task_id AND t.deleted_at IS NULL WHERE j.status IN ('leased','running') GROUP BY j.kind`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var kind string
		var count int
		if err := rows.Scan(&kind, &count); err != nil {
			rows.Close()
			return nil, err
		}
		leasesByKind[kind] = count
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	serviceStatus := "healthy"
	for _, analyzer := range analyzers {
		if analyzer.Status != "available" {
			serviceStatus = "degraded"
		}
	}
	if bundle == nil || bundle.Status != "active" {
		serviceStatus = "degraded"
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return gin.H{"version": s.cfg.Version, "service_status": serviceStatus, "active_tasks": activeTasks, "queued_tasks": queuedTasks, "queue_depth": queueDepth, "task_counts": counts,
		"worker_summary":        gin.H{"observed_leases": observedLeases, "observed_owners": observedOwners, "leases_by_kind": leasesByKind, "oldest_heartbeat_at": nullableTime(oldestHeartbeat), "latest_heartbeat_at": nullableTime(latestHeartbeat)},
		"repository_used_bytes": nil, "repository_total_bytes": nil, "analyzers": analyzers, "trivy_database_bundle": bundle, "collected_at": now}, nil
}
