package disposition

import (
	"binaryscan.local/backend/internal/identity"
	"binaryscan.local/backend/internal/impact"
	"binaryscan.local/backend/internal/sbom"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

type Change struct {
	EnvironmentVersionID string     `json:"environmentVersionId"`
	Status               string     `json:"status"`
	Reason               string     `json:"reason"`
	ExpectedRevision     uint64     `json:"expectedRevision"`
	ExpiresAt            *time.Time `json:"expiresAt"`
	OverrideUntil        *time.Time `json:"overrideUntil"`
}
type Result struct {
	Status   string `json:"status"`
	Revision uint64 `json:"revision"`
	Source   string `json:"source"`
}
type Store struct{ DB *sql.DB }

func Event(ctx context.Context, tx *sql.Tx, occurrence, profile, key string, revision uint64, actor any, details any) error {
	id, e := identity.UUID()
	if e != nil {
		return e
	}
	b, e := json.Marshal(details)
	if e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO disposition_events(id,occurrence_id,environment_profile_id,revision,event_key,actor_id,details) VALUES(?,?,?,?,?,?,?)`, id, occurrence, profile, revision, key, actor, b)
	return e
}
func (s Store) Change(ctx context.Context, task, occurrence, key string, actor uint64, request Change) (Result, error) {
	var out Result
	now := time.Now().UTC()
	if request.Status != "open" && request.Status != "ignored" || len(request.Reason) < 1 || len(request.Reason) > 1024 || len(key) < 1 || len(key) > 128 {
		return out, fmt.Errorf("invalid_disposition_request")
	}
	if request.Status == "open" && (request.OverrideUntil == nil || !request.OverrideUntil.After(now)) {
		return out, fmt.Errorf("restore_override_expiry_required")
	}
	if request.ExpiresAt != nil && !request.ExpiresAt.After(now) {
		return out, fmt.Errorf("disposition_expiry_invalid")
	}
	env, e := (impact.Store{DB: s.DB}).Environment(ctx, request.EnvironmentVersionID)
	if e != nil {
		return out, e
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	var live string
	if e = tx.QueryRowContext(ctx, `SELECT o.id FROM vulnerability_occurrences o JOIN tasks t ON t.id=o.task_id WHERE o.id=? AND o.task_id=? AND t.deleted_at IS NULL FOR UPDATE`, occurrence, task).Scan(&live); e != nil {
		return out, e
	}
	requestHash := sbom.Digest(request)
	var prior []byte
	e = tx.QueryRowContext(ctx, `SELECT details FROM disposition_events WHERE occurrence_id=? AND environment_profile_id=? AND event_key=?`, occurrence, env.ProfileID, key).Scan(&prior)
	if e == nil {
		var old struct {
			RequestHash string `json:"requestHash"`
			Result      Result `json:"result"`
		}
		if e = json.Unmarshal(prior, &old); e != nil {
			return out, e
		}
		if old.RequestHash != requestHash {
			return out, fmt.Errorf("disposition_idempotency_conflict")
		}
		return old.Result, nil
	}
	if e != sql.ErrNoRows {
		return out, e
	}
	if _, e = tx.ExecContext(ctx, `INSERT IGNORE INTO vulnerability_dispositions(occurrence_id,environment_profile_id,environment_version_id,status,source) VALUES(?,?,?,'open','policy')`, occurrence, env.ProfileID, env.ID); e != nil {
		return out, e
	}
	var revision uint64
	var currentVersion string
	if e = tx.QueryRowContext(ctx, `SELECT revision,environment_version_id FROM vulnerability_dispositions WHERE occurrence_id=? AND environment_profile_id=? FOR UPDATE`, occurrence, env.ProfileID).Scan(&revision, &currentVersion); e != nil {
		return out, e
	}
	var currentEnv uint64
	if e = tx.QueryRowContext(ctx, `SELECT revision FROM environment_profiles WHERE id=? FOR UPDATE`, env.ProfileID).Scan(&currentEnv); e != nil {
		return out, e
	}
	if revision != request.ExpectedRevision || currentEnv != env.Revision {
		return out, fmt.Errorf("disposition_revision_conflict")
	}
	out = Result{Status: request.Status, Revision: revision + 1, Source: "manual"}
	if _, e = tx.ExecContext(ctx, `UPDATE vulnerability_dispositions SET environment_version_id=?,status=?,source='manual',revision=?,reason=?,override_until=?,expires_at=?,assessment_id=NULL,pending_run_id=NULL,updated_at=UTC_TIMESTAMP(6) WHERE occurrence_id=? AND environment_profile_id=?`, env.ID, out.Status, out.Revision, request.Reason, request.OverrideUntil, request.ExpiresAt, occurrence, env.ProfileID); e != nil {
		return out, e
	}
	if e = Event(ctx, tx, occurrence, env.ProfileID, key, out.Revision, actor, map[string]any{"requestHash": requestHash, "request": request, "result": out}); e != nil {
		return out, e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO audit_logs(actor_user_id,action,object_type,object_id,outcome,details) VALUES(?,'sca.disposition.change','vulnerability',?,'success',JSON_OBJECT('profileId',?,'status',?,'revision',?,'reason',?))`, actor, occurrence, env.ProfileID, out.Status, out.Revision, request.Reason); e != nil {
		return out, e
	}
	e = tx.Commit()
	return out, e
}
func ApplyAutomatic(ctx context.Context, tx *sql.Tx, a impact.Assessment, p impact.Policy, expected uint64, now time.Time) error {
	var revision uint64
	var source, status, environment string
	var override, expires sql.NullTime
	var pending sql.NullString
	e := tx.QueryRowContext(ctx, `SELECT revision,source,status,environment_version_id,override_until,expires_at,pending_run_id FROM vulnerability_dispositions WHERE occurrence_id=? AND environment_profile_id=? FOR UPDATE`, a.OccurrenceID, a.ProfileID).Scan(&revision, &source, &status, &environment, &override, &expires, &pending)
	if e != nil {
		return e
	}
	if revision != expected || environment != a.EnvironmentVersionID || pending.String != a.RunID {
		return nil
	}
	if source == "manual" && ((status == "open" && override.Valid && override.Time.After(now)) || (status == "ignored" && (!expires.Valid || expires.Time.After(now)))) {
		return nil
	}
	next := "open"
	if p.Mode == "automatic" && a.Excluded && a.ValidUntil.After(now) {
		next = "ignored"
	}
	revision++
	if _, e = tx.ExecContext(ctx, `UPDATE vulnerability_dispositions SET status=?,source='policy',revision=?,assessment_id=?,reason=?,expires_at=?,override_until=NULL,pending_run_id=NULL,updated_at=UTC_TIMESTAMP(6) WHERE occurrence_id=? AND environment_profile_id=?`, next, revision, a.ID, a.Reason, a.ValidUntil, a.OccurrenceID, a.ProfileID); e != nil {
		return e
	}
	if e = Event(ctx, tx, a.OccurrenceID, a.ProfileID, "analysis:"+a.RunID, revision, nil, map[string]any{"status": next, "source": "policy", "assessment": a}); e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO audit_logs(action,object_type,object_id,outcome,details) VALUES('sca.disposition.policy','vulnerability',?,'success',JSON_OBJECT('analysisId',?,'status',?,'reason',?))`, a.OccurrenceID, a.ID, next, a.Reason)
	return e
}
