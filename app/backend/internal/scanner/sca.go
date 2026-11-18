package scanner

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"binaryscan.local/backend/internal/identity"
	"binaryscan.local/backend/internal/job"
	"binaryscan.local/backend/internal/jvmarchive"
	"binaryscan.local/backend/internal/sbom"
	"binaryscan.local/backend/internal/sca"
)

func (e *Executor) scaSubject(ctx context.Context, runID string) (subject, []byte, error) {
	var s subject
	var request []byte
	err := e.db.QueryRowContext(ctx, `SELECT t.id,f.id,f.logical_path,b.storage_key,COALESCE(t.analysis_mode,''),f.detected_format,COALESCE(r.request,JSON_OBJECT())
 FROM runs r JOIN tasks t ON t.id=r.task_id AND t.deleted_at IS NULL JOIN file_nodes f ON f.task_id=t.id AND f.parent_id IS NULL AND f.blob_id=t.blob_id JOIN blobs b ON b.id=f.blob_id AND b.state='ready'
 WHERE r.id=? LIMIT 1`, runID).Scan(&s.taskID, &s.fileID, &s.logicalPath, &s.storageKey, &s.inputCategory, &s.detectedFormat, &request)
	return s, request, err
}
func (e *Executor) parseSBOM(ctx context.Context, claim job.Claim) error {
	s, raw, err := e.scaSubject(ctx, claim.RunID)
	if err != nil {
		return err
	}
	input, err := e.blobPath(s.storageKey)
	if err != nil {
		return err
	}
	info, err := os.Stat(input)
	if err != nil {
		return err
	}
	if info.Size() > sbom.MaxBytes {
		return fmt.Errorf("SBOM_LIMIT_EXCEEDED")
	}
	body, err := os.ReadFile(input)
	if err != nil {
		return err
	}
	job.ReportProgress(ctx, "sbom-validation", 0, 0, "components")
	d, err := sbom.Parse(ctx, body, "")
	if err != nil {
		return err
	}
	if d.Standard == "SWID" {
		for i := range d.Components {
			d.Components[i].Path = s.logicalPath
		}
		if err = sbom.Finalize(&d); err != nil {
			return err
		}
	}
	var collection sbom.CollectionRequest
	if err = json.Unmarshal(raw, &collection); err != nil {
		return err
	}
	if len(collection.Members) > 0 {
		tags := []sbom.LocalTag{}
		for _, member := range collection.Members {
			if err = sca.TaskLive(ctx, e.db, member.TaskID); err != nil {
				return err
			}
			inv, x := (sca.Store{DB: e.db}).Inventory(ctx, member.TaskID, member.InventoryID)
			if x != nil {
				return x
			}
			if inv.Document.Fingerprint != member.Fingerprint {
				return fmt.Errorf("SWID_COLLECTION_SNAPSHOT_CONFLICT")
			}
			tags = append(tags, sbom.LocalTag{Document: inv.Document, LogicalPath: member.LogicalPath})
		}
		d, err = sbom.SWIDCollection(tags, collection.IdentityMappings)
		if err != nil {
			return err
		}
	}
	return e.jobs.WithFence(ctx, claim, func(tx *sql.Tx) error {
		inventoryID, err := sca.PublishInventory(ctx, tx, s.taskID, claim.RunID, d)
		if err != nil {
			return err
		}
		docID, err := identity.UUID()
		if err != nil {
			return err
		}
		diagnostics, _ := json.Marshal(d.Diagnostics)
		if _, err = tx.ExecContext(ctx, `INSERT INTO sbom_documents(id,task_id,run_id,standard,spec_version,encoding,input_sha256,parser_version,diagnostics) VALUES(?,?,?,?,?,?,?,?,?)`, docID, s.taskID, claim.RunID, d.Standard, d.SpecVersion, d.Encoding, d.InputSHA256, sbom.Version, diagnostics); err != nil {
			return err
		}
		if err = e.recordSCAArtifact(ctx, tx, claim, s.taskID, "sbom-normalized-json", d); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE runs SET tool_name='sbom-normalizer',tool_version=?,result_quality=? WHERE id=?`, sbom.Version, d.Quality, claim.RunID); err != nil {
			return err
		}
		return queueSCARun(ctx, tx, s.taskID, s.fileID, claim.RunID, job.KindSCAScan, map[string]any{"inventoryId": inventoryID})
	})
}
func queueSCARun(ctx context.Context, tx *sql.Tx, taskID, fileID, parent string, kind job.Kind, request any) error {
	id, err := identity.UUID()
	if err != nil {
		return err
	}
	b, err := json.Marshal(request)
	if err != nil {
		return err
	}
	key := "sca-child:" + parent + ":" + string(kind)
	if _, err = tx.ExecContext(ctx, `INSERT INTO runs(id,kind,status,task_id,subject_type,subject_id,created_by,idempotency_key,request)
 SELECT ?,?,'queued',id,'file_node',?,created_by,?,? FROM tasks WHERE id=? ON DUPLICATE KEY UPDATE id=runs.id`, id, kind, fileID, key, b, taskID); err != nil {
		return err
	}
	if err = tx.QueryRowContext(ctx, `SELECT id FROM runs WHERE task_id=? AND subject_id=? AND kind=? AND idempotency_key=?`, taskID, fileID, kind, key).Scan(&id); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO jobs(run_id,kind,status,max_attempts) VALUES(?,?,'queued',20) ON DUPLICATE KEY UPDATE run_id=run_id`, id, kind)
	return err
}
func (e *Executor) scanSCA(ctx context.Context, claim job.Claim) error {
	s, raw, err := e.scaSubject(ctx, claim.RunID)
	if err != nil {
		return err
	}
	var request struct {
		InventoryID string `json:"inventoryId"`
	}
	if err = json.Unmarshal(raw, &request); err != nil {
		return err
	}
	var d sbom.Document
	inventoryID := request.InventoryID
	if inventoryID != "" {
		v, err := (sca.Store{DB: e.db}).Inventory(ctx, s.taskID, inventoryID)
		if err != nil {
			return err
		}
		d = v.Document
	} else {
		input, err := e.blobPath(s.storageKey)
		if err != nil {
			return err
		}
		job.ReportProgress(ctx, "java-inventory", 0, 0, "components")
		d, err = jvmarchive.Inventory(ctx, input, s.logicalPath)
		if err != nil {
			return err
		}
	}
	work, err := os.MkdirTemp(e.cfg.Worker.WorkRoot, "sca-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	body, err := sbom.CycloneDX(d)
	if err != nil {
		return err
	}
	scanInput := filepath.Join(work, "inventory.cdx.json")
	if err = os.WriteFile(scanInput, body, 0600); err != nil {
		return err
	}
	cache, err := prepareTrivyCache(e.cfg.Worker.TrivyCacheRoot, work)
	if err != nil {
		return err
	}
	reportPath := filepath.Join(work, "trivy.json")
	executionCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(executionCtx, e.cfg.Worker.TrivyPath, "sbom", "--cache-dir", cache, "--skip-db-update", "--skip-java-db-update", "--offline-scan", "--scanners", "vuln", "--format", "json", "--output", reportPath, scanInput)
	var stderr scaLog
	cmd.Stderr = &stderr
	job.ReportProgress(ctx, "component-vulnerabilities", 0, int64(len(d.Components)), "components")
	if err = cmd.Run(); err != nil {
		return fmt.Errorf("SCA_SCANNER_FAILED: %w: %s", err, stderr.String())
	}
	info, err := os.Stat(reportPath)
	if err != nil {
		return err
	}
	if info.Size() > maxTrivyReportBytes {
		return fmt.Errorf("SCA_REPORT_LIMIT_EXCEEDED")
	}
	report, err := os.ReadFile(reportPath)
	if err != nil {
		return err
	}
	findings, diagnostics, err := sca.Findings(report, d)
	if err != nil {
		return err
	}
	d.Diagnostics = append(d.Diagnostics, diagnostics...)
	if len(diagnostics) > 0 {
		d.Quality = "partial"
	}
	dbMeta, _ := os.ReadFile(filepath.Join(e.cfg.Worker.TrivyCacheRoot, "db", "metadata.json"))
	dbDigest := sbom.BytesDigest(dbMeta)
	return e.jobs.WithFence(ctx, claim, func(tx *sql.Tx) error {
		if inventoryID == "" {
			inventoryID, err = sca.PublishInventory(ctx, tx, s.taskID, claim.RunID, d)
			if err != nil {
				return err
			}
		}
		if err = sca.PublishFindings(ctx, tx, s.taskID, claim.RunID, inventoryID, d, findings); err != nil {
			return err
		}
		if err = e.recordSCAArtifact(ctx, tx, claim, s.taskID, "sca-scan-json", map[string]any{"schemaVersion": sca.Version, "inventoryId": inventoryID, "inputSha256": d.InputSHA256, "quality": d.Quality, "diagnostics": d.Diagnostics, "databaseDigest": dbDigest, "databaseMetadata": json.RawMessage(dbMeta), "findings": findings}); err != nil {
			return err
		}
		if err = e.recordSCAArtifact(ctx, tx, claim, s.taskID, "sca-trivy-json", json.RawMessage(report)); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE runs SET tool_name='trivy-sbom',tool_version='0.74.0',ruleset_version=?,result_quality=? WHERE id=?`, dbDigest, d.Quality, claim.RunID)
		return err
	})
}

type scaLog struct{ bytes.Buffer }

func (b *scaLog) Write(p []byte) (int, error) {
	n := len(p)
	if b.Len() < 8192 {
		if len(p) > 8192-b.Len() {
			p = p[:8192-b.Len()]
		}
		b.Buffer.Write(p)
	}
	return n, nil
}
func (e *Executor) recordSCAArtifact(ctx context.Context, tx *sql.Tx, claim job.Claim, taskID, kind string, value any) error {
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(e.cfg.Worker.WorkRoot, "sca-artifact-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err = tmp.Write(body); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	key, size, err := publishArtifact(e.cfg.Worker.ArtifactRoot, taskID, claim.RunID, claim.FencingToken, strings.ReplaceAll(kind, "/", "-")+".json", name)
	if err != nil {
		return err
	}
	id, err := identity.UUID()
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO run_artifacts(id,task_id,run_id,artifact_kind,media_type,storage_key,size_bytes,sha256,schema_version,state) VALUES(?,?,?,?,'application/json',?,?,UNHEX(?),?,'ready')`, id, taskID, claim.RunID, kind, key, size, sbom.BytesDigest(body), sca.Version)
	return err
}
