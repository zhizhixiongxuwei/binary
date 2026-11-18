package scanner

import (
	"binaryscan.local/backend/internal/disposition"
	"binaryscan.local/backend/internal/impact"
	"binaryscan.local/backend/internal/job"
	"binaryscan.local/backend/internal/sbom"
	"binaryscan.local/backend/internal/sca"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

type impactRunRequest struct {
	SCARunID             string            `json:"scaRunId"`
	InventoryID          string            `json:"inventoryId"`
	EnvironmentVersionID string            `json:"environmentVersionId"`
	PolicyID             string            `json:"policyId"`
	KnowledgeDigest      string            `json:"knowledgeDigest"`
	Revisions            map[string]uint64 `json:"revisions"`
}

func (e *Executor) analyzeImpact(ctx context.Context, claim job.Claim) error {
	subject, body, err := e.scaSubject(ctx, claim.RunID)
	if err != nil {
		return err
	}
	var request impactRunRequest
	if err = json.Unmarshal(body, &request); err != nil {
		return err
	}
	store := impact.Store{DB: e.db}
	env, err := store.Environment(ctx, request.EnvironmentVersionID)
	if err != nil {
		return err
	}
	policy, err := store.Policy(ctx, subject.taskID, request.PolicyID)
	if err != nil {
		return err
	}
	bundle, err := impact.Rules()
	if err != nil {
		return err
	}
	if bundle.Digest != request.KnowledgeDigest {
		return fmt.Errorf("IMPACT_KNOWLEDGE_CHANGED_REQUEUE_REQUIRED")
	}
	inventory, err := (sca.Store{DB: e.db}).Inventory(ctx, subject.taskID, request.InventoryID)
	if err != nil {
		return err
	}
	rows, err := e.db.QueryContext(ctx, `SELECT DISTINCT o.id,o.details FROM vulnerability_occurrences o JOIN occurrence_findings f ON f.occurrence_id=o.id JOIN findings raw ON raw.id=f.finding_id WHERE o.task_id=? AND f.inventory_id=? AND raw.run_id=? ORDER BY o.id`, subject.taskID, request.InventoryID, request.SCARunID)
	if err != nil {
		return err
	}
	occurrences := []sca.Occurrence{}
	for rows.Next() {
		var o sca.Occurrence
		var b []byte
		if err = rows.Scan(&o.ID, &b); err != nil {
			rows.Close()
			return err
		}
		if err = json.Unmarshal(b, &o.Vulnerability); err != nil {
			rows.Close()
			return err
		}
		occurrences = append(occurrences, o)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	rules := map[string]*impact.Rule{}
	targets := []impact.Target{}
	for _, o := range occurrences {
		for i := range bundle.Rules {
			rule := &bundle.Rules[i]
			if o.Vulnerability.Component.Quality == "identified" && rule.Vulnerability == o.Vulnerability.ID && strings.HasPrefix(o.Vulnerability.Component.PURL, rule.PURLPrefix) {
				rules[o.ID] = rule
				if len(rule.TargetClassPrefixes) > 0 && policy.Config.Reachability {
					targets = append(targets, impact.Target{OccurrenceID: o.ID, ComponentPath: o.Vulnerability.Component.Path, RuleID: rule.ID, Prefixes: rule.TargetClassPrefixes})
				}
				break
			}
		}
	}
	java := impact.JavaResponse{Results: map[string]impact.CodeResult{}}
	job.ReportProgress(ctx, "impact-code", 0, int64(len(targets)), "vulnerabilities")
	if len(targets) > 0 && subject.inputCategory == "java_sca" {
		input, err := e.blobPath(subject.storageKey)
		if err != nil {
			return err
		}
		info, err := os.Stat(input)
		if err != nil {
			return err
		}
		if info.Size() > 256<<20 {
			return fmt.Errorf("IMPACT_INPUT_LIMIT")
		}
		root, err := os.ReadFile(input)
		if err != nil {
			return err
		}
		if sbom.BytesDigest(root) != inventory.Document.InputSHA256 {
			return fmt.Errorf("IMPACT_INPUT_CHANGED")
		}
		inputs := []impact.Input{{SHA256: inventory.Document.InputSHA256, LogicalPath: subject.logicalPath, Size: info.Size(), Filename: input}}
		for _, taskID := range env.Config.ExternalDependencies {
			var key, name, digest string
			var size int64
			err = e.db.QueryRowContext(ctx, `SELECT b.storage_key,t.display_name,LOWER(HEX(b.sha256)),b.size_bytes FROM tasks t JOIN blobs b ON b.id=t.blob_id AND b.state='ready' WHERE t.id=? AND t.deleted_at IS NULL AND t.detected_format IN ('jar','war')`, taskID).Scan(&key, &name, &digest, &size)
			if err != nil {
				return fmt.Errorf("EXTERNAL_DEPENDENCY_UNAVAILABLE: %w", err)
			}
			filename, err := e.blobPath(key)
			if err != nil {
				return err
			}
			inputs = append(inputs, impact.Input{SHA256: digest, LogicalPath: "external:" + taskID + "/" + name, Size: size, Filename: filename})
		}
		java, err = impact.CallJava(ctx, e.cfg.Worker.JavaCheckerURL, impact.JavaRequest{Schema: "java-impact-v1", InputSHA256: inventory.Document.InputSHA256, JavaRelease: env.Config.JavaRelease, ApplicationType: env.Config.ApplicationType, EntryPoints: env.Config.EntryPoints, Inputs: inputs, Targets: targets})
		if err != nil {
			if strings.Contains(err.Error(), "UNAVAILABLE") || strings.Contains(err.Error(), "connect") {
				return job.Retryable(err, 5*time.Second)
			}
			return err
		}
	}
	assessments := []impact.Assessment{}
	now := time.Now().UTC()
	for _, o := range occurrences {
		code := java.Results[o.ID]
		if code.State == "" {
			code.State = "unknown"
			code.Diagnostics = []string{"BYTECODE_OR_RULE_MAPPING_UNAVAILABLE"}
		}
		assessments = append(assessments, impact.Evaluate(o.ID, claim.RunID, env, policy, bundle, rules[o.ID], code, now))
	}
	return e.jobs.WithFence(ctx, claim, func(tx *sql.Tx) error {
		var currentRevision uint64
		if err = tx.QueryRowContext(ctx, `SELECT revision FROM environment_profiles WHERE id=? FOR UPDATE`, env.ProfileID).Scan(&currentRevision); err != nil {
			return err
		}
		active := currentRevision == env.Revision
		currentBundle, err := impact.Rules()
		if err != nil {
			return err
		}
		active = active && currentBundle.Digest == bundle.Digest
		for _, a := range assessments {
			b, _ := json.Marshal(a)
			if _, err = tx.ExecContext(ctx, `INSERT INTO vulnerability_assessments(id,occurrence_id,run_id,environment_version_id,policy_id,knowledge_digest,reachability,environment_applicability,attack_preconditions,details) VALUES(?,?,?,?,?,?,?,?,?,?)`, a.ID, a.OccurrenceID, a.RunID, env.ID, policy.ID, bundle.Digest, a.Reachability, a.Environment, a.Attack, b); err != nil {
				return err
			}
			if active {
				if err = disposition.ApplyAutomatic(ctx, tx, a, policy.Config, request.Revisions[a.OccurrenceID], now); err != nil {
					return err
				}
			}
		}
		if err = e.recordSCAArtifact(ctx, tx, claim, subject.taskID, "impact-analysis-json", map[string]any{"schemaVersion": impact.Version, "environment": env, "policy": policy, "knowledge": bundle, "inventoryFingerprint": inventory.Document.Fingerprint, "code": java, "assessments": assessments, "active": active}); err != nil {
			return err
		}
		quality := "complete"
		for _, a := range assessments {
			if a.Reachability == "unknown" || a.Environment == "unknown" || a.Attack == "unknown" {
				quality = "partial"
			}
		}
		_, err = tx.ExecContext(ctx, `UPDATE runs SET tool_name='java-impact',tool_version=?,ruleset_version=?,result_quality=? WHERE id=?`, impact.Version, bundle.Digest, quality, claim.RunID)
		return err
	})
}
