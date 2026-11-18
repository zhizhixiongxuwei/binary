package impact

import (
	"binaryscan.local/backend/internal/sbom"
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

func (s Store) Maintain(ctx context.Context) error {
	bundle, e := Rules()
	if e != nil {
		return e
	}
	manifest, _ := json.Marshal(bundle)
	if _, e = s.DB.ExecContext(ctx, `INSERT INTO analysis_rule_bundles(digest,version,manifest) VALUES(?,?,?) ON DUPLICATE KEY UPDATE digest=digest`, bundle.Digest, bundle.Version, manifest); e != nil {
		return e
	}
	rows, e := s.DB.QueryContext(ctx, `SELECT DISTINCT o.task_id,t.created_by,d.occurrence_id,d.revision,latest.id,
 JSON_UNQUOTE(JSON_EXTRACT(r.request,'$.scaRunId')),JSON_UNQUOTE(JSON_EXTRACT(r.request,'$.inventoryId')),JSON_UNQUOTE(JSON_EXTRACT(r.request,'$.policyId'))
 FROM vulnerability_dispositions d JOIN vulnerability_occurrences o ON o.id=d.occurrence_id JOIN tasks t ON t.id=o.task_id AND t.deleted_at IS NULL
 JOIN environment_versions old ON old.id=d.environment_version_id JOIN environment_profiles p ON p.id=old.profile_id
 JOIN environment_versions latest ON latest.profile_id=p.id AND latest.revision=p.revision
 JOIN runs r ON r.id=(SELECT last_run.id FROM runs last_run JOIN environment_versions last_env ON last_env.id=JSON_UNQUOTE(JSON_EXTRACT(last_run.request,'$.environmentVersionId')) WHERE last_run.task_id=o.task_id AND last_run.kind='impact_analysis' AND last_env.profile_id=p.id ORDER BY last_run.created_at DESC,last_run.id DESC LIMIT 1)
 LEFT JOIN vulnerability_assessments a ON a.id=d.assessment_id
 WHERE (d.expires_at<=UTC_TIMESTAMP(6) OR old.revision<>p.revision OR (d.source='policy' AND a.knowledge_digest<>?) OR (d.source='manual' AND d.status='open' AND d.override_until<=UTC_TIMESTAMP(6)))
 AND (old.revision<>p.revision OR NOT EXISTS(SELECT 1 FROM runs pending WHERE pending.id=d.pending_run_id AND pending.status IN ('queued','running')))
 AND d.updated_at<DATE_SUB(UTC_TIMESTAMP(6),INTERVAL 30 SECOND) LIMIT 100`, bundle.Digest)
	if e != nil {
		return e
	}
	type candidate struct {
		Task, Occurrence, Environment, SCA, Inventory, Policy string
		User, Revision                                        uint64
	}
	items := []candidate{}
	for rows.Next() {
		var c candidate
		if e = rows.Scan(&c.Task, &c.User, &c.Occurrence, &c.Revision, &c.Environment, &c.SCA, &c.Inventory, &c.Policy); e != nil {
			rows.Close()
			return e
		}
		items = append(items, c)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	queued := map[string]bool{}
	failures := []error{}
	for _, c := range items {
		group := sbom.Digest([]string{c.Task, c.SCA, c.Inventory, c.Environment, c.Policy, bundle.Digest})
		if queued[group] {
			continue
		}
		key := "reevaluate:" + sbom.Digest([]string{c.Occurrence, fmt.Sprint(c.Revision), c.Environment, bundle.Digest})
		_, e = s.Queue(ctx, c.User, c.Task, key, RunRequest{SCARunID: c.SCA, InventoryID: c.Inventory, EnvironmentVersionID: c.Environment, PolicyID: c.Policy})
		if e != nil {
			failures = append(failures, e)
			continue
		}
		queued[group] = true
	}
	return errors.Join(failures...)
}
