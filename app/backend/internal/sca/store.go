package sca

import (
	"binaryscan.local/backend/internal/identity"
	"binaryscan.local/backend/internal/impact"
	"binaryscan.local/backend/internal/sbom"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type Querier interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}
type Store struct{ DB Querier }

func PublishInventory(ctx context.Context, tx *sql.Tx, taskID, runID string, d sbom.Document) (string, error) {
	id, e := identity.UUID()
	if e != nil {
		return "", e
	}
	body, e := json.Marshal(d)
	if e != nil {
		return "", e
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO component_inventories(id,task_id,run_id,input_sha256,fingerprint,source,quality,document) VALUES(?,?,?,?,?,?,?,?)`, id, taskID, runID, d.InputSHA256, d.Fingerprint, d.Standard, d.Quality, body)
	if e != nil {
		return "", e
	}
	for _, c := range d.Components {
		b, _ := json.Marshal(c)
		if _, e = tx.ExecContext(ctx, `INSERT INTO component_instances(id,inventory_id,identity_key,name,version,purl,logical_path,details) VALUES(?,?,?,?,?,?,?,?)`, c.ID, id, c.Identity, c.Name, c.Version, c.PURL, c.Path, b); e != nil {
			return "", e
		}
	}
	for _, r := range d.Dependencies {
		b, _ := json.Marshal(r)
		if _, e = tx.ExecContext(ctx, `INSERT IGNORE INTO component_dependencies(inventory_id,relation_key,details) VALUES(?,?,?)`, id, sbom.Digest(r), b); e != nil {
			return "", e
		}
	}
	return id, nil
}
func PublishFindings(ctx context.Context, tx *sql.Tx, taskID, runID, inventoryID string, d sbom.Document, findings []Vulnerability) error {
	for _, v := range findings {
		body, _ := json.Marshal(v)
		oid := sbom.Digest([]string{taskID, d.InputSHA256, v.Component.Identity, v.Component.Path, v.Component.SourceRef, v.ID})
		severity := v.Severity
		switch severity {
		case "critical", "high", "medium", "low", "info":
		default:
			severity = "info"
		}
		r, e := tx.ExecContext(ctx, `INSERT INTO findings(task_id,run_id,finding_type,severity,rule_id,external_id,logical_path,title,message,details) VALUES(?,?,'vulnerability',?,?,?,?,?,?,?)`, taskID, runID, severity, v.ID, v.ID, v.Component.Path, v.Title, v.Description, body)
		if e != nil {
			return e
		}
		fid, e := r.LastInsertId()
		if e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, `INSERT INTO vulnerability_occurrences(id,task_id,input_sha256,component_id,vulnerability_id,severity,details) VALUES(?,?,?,?,?,?,?) ON DUPLICATE KEY UPDATE id=id`, oid, taskID, d.InputSHA256, v.ComponentID, v.ID, severity, body); e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, `INSERT INTO occurrence_findings(occurrence_id,finding_id,inventory_id) VALUES(?,?,?)`, oid, fid, inventoryID); e != nil {
			return e
		}
	}
	return nil
}
func (s Store) Inventories(ctx context.Context, taskID string) ([]Inventory, error) {
	rows, e := s.DB.QueryContext(ctx, `SELECT id,run_id,JSON_REMOVE(document,'$.components','$.dependencies'),created_at,JSON_LENGTH(document,'$.components'),JSON_LENGTH(document,'$.dependencies') FROM component_inventories WHERE task_id=? ORDER BY created_at DESC,id DESC LIMIT 100`, taskID)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Inventory{}
	for rows.Next() {
		var v Inventory
		var b []byte
		var at time.Time
		v.TaskID = taskID
		if e = rows.Scan(&v.ID, &v.RunID, &b, &at, &v.ComponentCount, &v.DependencyCount); e != nil {
			return nil, e
		}
		if e = json.Unmarshal(b, &v.Document); e != nil {
			return nil, e
		}
		v.CreatedAt = at.Format(time.RFC3339Nano)
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s Store) Inventory(ctx context.Context, taskID, id string) (Inventory, error) {
	var v Inventory
	var b []byte
	var at time.Time
	e := s.DB.QueryRowContext(ctx, `SELECT id,run_id,document,created_at FROM component_inventories WHERE task_id=? AND id=?`, taskID, id).Scan(&v.ID, &v.RunID, &b, &at)
	if e != nil {
		return v, e
	}
	v.TaskID = taskID
	v.CreatedAt = at.Format(time.RFC3339Nano)
	e = json.Unmarshal(b, &v.Document)
	return v, e
}

type Filter struct {
	ID, Status, Severity, Reachability, Environment, Attack, Source string
	ProfileID                                                       string
	RunIDs                                                          []string
}

func ignoredSQL(alias string) string {
	return `(EXISTS(SELECT 1 FROM vulnerability_dispositions ds WHERE ds.occurrence_id=` + alias + `.id) AND NOT EXISTS(SELECT 1 FROM vulnerability_dispositions ds JOIN environment_versions ev ON ev.id=ds.environment_version_id JOIN environment_profiles ep ON ep.id=ev.profile_id LEFT JOIN vulnerability_assessments va ON va.id=ds.assessment_id LEFT JOIN runs ar ON ar.id=va.run_id WHERE ds.occurrence_id=` + alias + `.id AND (ds.status<>'ignored' OR ev.revision<>ep.revision OR (ds.expires_at IS NOT NULL AND ds.expires_at<=UTC_TIMESTAMP(6)) OR (ds.source='policy' AND (va.id IS NULL OR va.knowledge_digest<>? OR ar.status NOT IN ('complete','partial'))))))`
}
func (s Store) Occurrences(ctx context.Context, taskID, cursor string, limit int, filters ...Filter) ([]Occurrence, error) {
	bundle, err := impact.Rules()
	if err != nil {
		return nil, err
	}
	if limit < 1 || limit > 200 {
		limit = 100
	}
	where := "o.task_id=? AND o.id>?"
	args := []any{taskID, cursor}
	if len(filters) > 0 {
		f := filters[0]
		if len(f.RunIDs) > 0 {
			placeholders := strings.TrimSuffix(strings.Repeat("?,", len(f.RunIDs)), ",")
			where += " AND (EXISTS(SELECT 1 FROM occurrence_findings ofi JOIN findings raw ON raw.id=ofi.finding_id WHERE ofi.occurrence_id=o.id AND raw.run_id IN (" + placeholders + ")) OR EXISTS(SELECT 1 FROM vulnerability_assessments va WHERE va.occurrence_id=o.id AND va.run_id IN (" + placeholders + ")))"
			for _, id := range f.RunIDs {
				args = append(args, id)
			}
			for _, id := range f.RunIDs {
				args = append(args, id)
			}
		}
		if f.ID != "" {
			where += " AND o.id=?"
			args = append(args, f.ID)
		}
		if f.Severity != "" {
			where += " AND o.severity=?"
			args = append(args, f.Severity)
		}
		if f.Status == "ignored" || f.Status == "open" {
			where += " AND "
			if f.Status == "open" {
				where += "NOT "
			}
			where += ignoredSQL("o")
			args = append(args, bundle.Digest)
		}
		if f.Source != "" {
			where += " AND EXISTS(SELECT 1 FROM vulnerability_dispositions ds WHERE ds.occurrence_id=o.id AND ds.source=? AND (?='' OR ds.environment_profile_id=?))"
			args = append(args, f.Source)
			args = append(args, f.ProfileID, f.ProfileID)
		}
		for _, pair := range [][2]string{{"reachability", f.Reachability}, {"environment_applicability", f.Environment}, {"attack_preconditions", f.Attack}} {
			if pair[1] != "" {
				valid := ` FROM vulnerability_dispositions ds JOIN vulnerability_assessments va ON va.id=ds.assessment_id JOIN environment_versions ev ON ev.id=ds.environment_version_id JOIN environment_profiles ep ON ep.id=ev.profile_id JOIN runs ar ON ar.id=va.run_id WHERE ds.occurrence_id=o.id AND (?='' OR ds.environment_profile_id=?) AND ev.revision=ep.revision AND (ds.expires_at IS NULL OR ds.expires_at>UTC_TIMESTAMP(6)) AND va.knowledge_digest=? AND ar.status IN ('complete','partial')`
				where += " AND (EXISTS(SELECT 1" + valid + " AND va." + pair[0] + "=?)"
				args = append(args, f.ProfileID, f.ProfileID, bundle.Digest, pair[1])
				if pair[1] == "unknown" || pair[1] == "not_analyzed" {
					where += " OR NOT EXISTS(SELECT 1" + valid + ")"
					args = append(args, f.ProfileID, f.ProfileID, bundle.Digest)
				}
				where += ")"
			}
		}
	}
	args = append(args, limit)
	rows, e := s.DB.QueryContext(ctx, `SELECT o.id,o.details FROM vulnerability_occurrences o WHERE `+where+` ORDER BY o.id LIMIT ?`, args...)
	if e != nil {
		return nil, e
	}
	out := []Occurrence{}
	for rows.Next() {
		var v Occurrence
		var b []byte
		v.TaskID = taskID
		v.Status = "open"
		if e = rows.Scan(&v.ID, &b); e != nil {
			rows.Close()
			return nil, e
		}
		if e = json.Unmarshal(b, &v.Vulnerability); e != nil {
			rows.Close()
			return nil, e
		}
		out = append(out, v)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	for i := range out {
		v := &out[i]
		v.Assessments = []json.RawMessage{}
		v.Dispositions = []ScopeDisposition{}
		rs, e := s.DB.QueryContext(ctx, `SELECT a.details FROM vulnerability_assessments a WHERE a.occurrence_id=? ORDER BY a.created_at DESC,a.id DESC LIMIT 100`, v.ID)
		if e != nil {
			return nil, e
		}
		for rs.Next() {
			var b []byte
			if e = rs.Scan(&b); e != nil {
				rs.Close()
				return nil, e
			}
			v.Assessments = append(v.Assessments, json.RawMessage(b))
		}
		e = rs.Err()
		rs.Close()
		if e != nil {
			return nil, e
		}
		ds, e := s.DB.QueryContext(ctx, `SELECT d.environment_profile_id,d.environment_version_id,COALESCE(d.assessment_id,''),d.status,d.source,d.revision,d.reason,d.expires_at,d.override_until,
   (e.revision=p.revision AND (d.expires_at IS NULL OR d.expires_at>UTC_TIMESTAMP(6)) AND (d.source='manual' OR EXISTS(SELECT 1 FROM vulnerability_assessments a JOIN runs r ON r.id=a.run_id WHERE a.id=d.assessment_id AND r.status IN ('complete','partial') AND a.knowledge_digest=?)))
   FROM vulnerability_dispositions d JOIN environment_versions e ON e.id=d.environment_version_id JOIN environment_profiles p ON p.id=e.profile_id WHERE d.occurrence_id=?`, bundle.Digest, v.ID)
		if e != nil {
			return nil, e
		}
		allIgnored := true
		for ds.Next() {
			var d ScopeDisposition
			var expires, override sql.NullTime
			var valid bool
			if e = ds.Scan(&d.ProfileID, &d.EnvironmentVersionID, &d.AssessmentID, &d.Status, &d.Source, &d.Revision, &d.Reason, &expires, &override, &valid); e != nil {
				ds.Close()
				return nil, e
			}
			d.Validity = "valid"
			if !valid {
				d.Validity = "stale"
				d.Status = "open"
			}
			if expires.Valid {
				d.ExpiresAt = expires.Time.Format(time.RFC3339Nano)
			}
			if override.Valid {
				d.OverrideUntil = override.Time.Format(time.RFC3339Nano)
			}
			if d.Status != "ignored" {
				allIgnored = false
			}
			v.Dispositions = append(v.Dispositions, d)
		}
		e = ds.Err()
		ds.Close()
		if e != nil {
			return nil, e
		}
		if len(v.Dispositions) > 0 && allIgnored {
			v.Status = "ignored"
		}
	}
	return out, nil
}
func (s Store) Summary(ctx context.Context, taskID string) (map[string]int, error) {
	bundle, e := impact.Rules()
	if e != nil {
		return nil, e
	}
	var total, unique, ignored, unknown int
	e = s.DB.QueryRowContext(ctx, `SELECT COUNT(*),COUNT(DISTINCT vulnerability_id),COALESCE(SUM(`+ignoredSQL("o")+`),0),COALESCE(SUM(NOT EXISTS(SELECT 1 FROM vulnerability_assessments a WHERE a.occurrence_id=o.id) OR EXISTS(SELECT 1 FROM vulnerability_dispositions ds LEFT JOIN vulnerability_assessments a ON a.id=ds.assessment_id WHERE ds.occurrence_id=o.id AND (a.id IS NULL OR a.reachability='unknown' OR a.environment_applicability='unknown' OR a.attack_preconditions='unknown'))),0) FROM vulnerability_occurrences o WHERE task_id=?`, bundle.Digest, taskID).Scan(&total, &unique, &ignored, &unknown)
	if e != nil {
		return nil, e
	}
	return map[string]int{"total": total, "uniqueVulnerabilities": unique, "ignored": ignored, "open": total - ignored, "unknown": unknown}, nil
}
func TaskLive(ctx context.Context, db *sql.DB, taskID string) error {
	var n int
	e := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM tasks WHERE id=? AND deleted_at IS NULL AND status NOT IN ('deleting','deleted')`, taskID).Scan(&n)
	if e == nil && n != 1 {
		return fmt.Errorf("task_not_found")
	}
	return e
}
