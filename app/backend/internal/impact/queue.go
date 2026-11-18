package impact

import (
	"binaryscan.local/backend/internal/identity"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
)

type RunRequest struct {
	SCARunID             string            `json:"scaRunId"`
	InventoryID          string            `json:"inventoryId"`
	EnvironmentVersionID string            `json:"environmentVersionId"`
	PolicyID             string            `json:"policyId"`
	KnowledgeDigest      string            `json:"knowledgeDigest"`
	Revisions            map[string]uint64 `json:"revisions"`
}
type QueueResult struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Created bool   `json:"created"`
}

func (s Store) Queue(ctx context.Context, user uint64, task, key string, request RunRequest) (QueueResult, error) {
	var out QueueResult
	if key == "" || len(key) > 128 {
		return out, fmt.Errorf("idempotency_key_required")
	}
	env, e := s.Environment(ctx, request.EnvironmentVersionID)
	if e != nil {
		return out, e
	}
	if _, e = s.Policy(ctx, task, request.PolicyID); e != nil {
		return out, e
	}
	bundle, e := Rules()
	if e != nil {
		return out, e
	}
	request.KnowledgeDigest = bundle.Digest
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	var live string
	if e = tx.QueryRowContext(ctx, `SELECT id FROM tasks WHERE id=? AND deleted_at IS NULL FOR UPDATE`, task).Scan(&live); e != nil {
		return out, e
	}
	var old []byte
	e = tx.QueryRowContext(ctx, `SELECT id,status,request FROM runs WHERE created_by=? AND kind='impact_analysis' AND subject_id=? AND idempotency_key=?`, user, task, key).Scan(&out.ID, &out.Status, &old)
	if e == nil {
		var previous RunRequest
		if e = json.Unmarshal(old, &previous); e != nil {
			return out, e
		}
		if previous.SCARunID != request.SCARunID || previous.InventoryID != request.InventoryID || previous.EnvironmentVersionID != request.EnvironmentVersionID || previous.PolicyID != request.PolicyID || previous.KnowledgeDigest != request.KnowledgeDigest {
			return out, fmt.Errorf("impact_idempotency_conflict")
		}
		return out, nil
	}
	if e != sql.ErrNoRows {
		return out, e
	}
	var valid int
	if e = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM runs r JOIN component_inventories i ON i.task_id=r.task_id AND (i.run_id=r.id OR JSON_UNQUOTE(JSON_EXTRACT(r.request,'$.inventoryId'))=i.id) WHERE r.id=? AND r.task_id=? AND r.kind='sca_scan' AND r.status IN ('complete','partial') AND i.id=?`, request.SCARunID, task, request.InventoryID).Scan(&valid); e != nil {
		return out, e
	}
	if valid != 1 {
		return out, fmt.Errorf("sca_snapshot_conflict")
	}
	var current uint64
	if e = tx.QueryRowContext(ctx, `SELECT revision FROM environment_profiles WHERE id=? FOR UPDATE`, env.ProfileID).Scan(&current); e != nil {
		return out, e
	}
	if current != env.Revision {
		return out, fmt.Errorf("environment_revision_conflict")
	}
	id, e := identity.UUID()
	if e != nil {
		return out, e
	}
	request.Revisions = map[string]uint64{}
	rows, e := tx.QueryContext(ctx, `SELECT DISTINCT o.id FROM vulnerability_occurrences o JOIN occurrence_findings f ON f.occurrence_id=o.id JOIN findings raw ON raw.id=f.finding_id WHERE o.task_id=? AND f.inventory_id=? AND raw.run_id=? ORDER BY o.id`, task, request.InventoryID, request.SCARunID)
	if e != nil {
		return out, e
	}
	ids := []string{}
	for rows.Next() {
		var oid string
		if e = rows.Scan(&oid); e != nil {
			rows.Close()
			return out, e
		}
		ids = append(ids, oid)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return out, e
	}
	for _, oid := range ids {
		if _, e = tx.ExecContext(ctx, `INSERT IGNORE INTO vulnerability_dispositions(occurrence_id,environment_profile_id,environment_version_id) VALUES(?,?,?)`, oid, env.ProfileID, env.ID); e != nil {
			return out, e
		}
		// Launch itself advances the generation, making late older analyses stale.
		if _, e = tx.ExecContext(ctx, `UPDATE vulnerability_dispositions SET status=IF(source='policy' OR environment_version_id<>?,'open',status),source=IF(environment_version_id<>?,'policy',source),environment_version_id=?,revision=revision+1,pending_run_id=?,updated_at=UTC_TIMESTAMP(6) WHERE occurrence_id=? AND environment_profile_id=?`, env.ID, env.ID, env.ID, id, oid, env.ProfileID); e != nil {
			return out, e
		}
		var revision uint64
		if e = tx.QueryRowContext(ctx, `SELECT revision FROM vulnerability_dispositions WHERE occurrence_id=? AND environment_profile_id=?`, oid, env.ProfileID).Scan(&revision); e != nil {
			return out, e
		}
		request.Revisions[oid] = revision
		eventID, x := identity.UUID()
		if x != nil {
			return out, x
		}
		eventBody, _ := json.Marshal(map[string]any{"type": "analysis_queued", "runId": id, "environmentVersionId": env.ID, "revision": revision, "reason": "Previous policy conclusion is pending reevaluation; manual overrides remain effective"})
		if _, e = tx.ExecContext(ctx, `INSERT INTO disposition_events(id,occurrence_id,environment_profile_id,revision,event_key,actor_id,details) VALUES(?,?,?,?,?,?,?)`, eventID, oid, env.ProfileID, revision, "queued:"+id, user, eventBody); e != nil {
			return out, e
		}
	}
	body, _ := json.Marshal(request)
	manifest, _ := json.Marshal(bundle)
	if _, e = tx.ExecContext(ctx, `INSERT INTO analysis_rule_bundles(digest,version,manifest) VALUES(?,?,?) ON DUPLICATE KEY UPDATE digest=digest`, bundle.Digest, bundle.Version, manifest); e != nil {
		return out, e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO runs(id,kind,status,task_id,subject_type,subject_id,created_by,idempotency_key,request) VALUES(?,'impact_analysis','queued',?,'task',?,?,?,?)`, id, task, task, user, key, body); e != nil {
		return out, e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO jobs(run_id,kind,status,max_attempts) VALUES(?,'impact_analysis','queued',2880)`, id); e != nil {
		return out, e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO task_events(task_id,event_type,message) VALUES(?,'run.queued','三维漏洞影响分析已排队')`, task); e != nil {
		return out, e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO audit_logs(actor_user_id,action,object_type,object_id,outcome,details) VALUES(?,'sca.impact.queue','run',?,'success',?)`, user, id, body); e != nil {
		return out, e
	}
	if e = tx.Commit(); e != nil {
		return out, e
	}
	return QueueResult{ID: id, Status: "queued", Created: true}, nil
}
