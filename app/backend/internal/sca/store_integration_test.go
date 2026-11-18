package sca

import (
	"binaryscan.local/backend/internal/config"
	"binaryscan.local/backend/internal/database"
	"binaryscan.local/backend/internal/disposition"
	"binaryscan.local/backend/internal/identity"
	"binaryscan.local/backend/internal/impact"
	"binaryscan.local/backend/internal/sbom"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestInventoryAndOccurrencePersistence(t *testing.T) {
	host := os.Getenv("SCA_TEST_MYSQL_HOST")
	if host == "" {
		t.Skip("requires dedicated SCA fixture MySQL")
	}
	ctx := context.Background()
	db, e := database.Open(ctx, config.Database{Host: host, Port: "3306", Name: "sca_test", User: "root", Password: os.Getenv("SCA_TEST_MYSQL_PASSWORD")})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	uid, _ := identity.UUID()
	res, e := db.Exec(`INSERT INTO users(public_id,username,password_hash,role) VALUES(?,?,?,'operator')`, uid, "sca-"+uid, "fixture-not-login")
	if e != nil {
		t.Fatal(e)
	}
	actor, _ := res.LastInsertId()
	task, _ := identity.UUID()
	blob, _ := identity.UUID()
	run, _ := identity.UUID()
	if _, e = db.Exec(`INSERT INTO blobs(id,sha256,size_bytes,storage_key) VALUES(?,UNHEX(?),1,?)`, blob, sbom.Digest(uid), uid); e != nil {
		t.Fatal(e)
	}
	if _, e = db.Exec(`INSERT INTO tasks(id,created_by,blob_id,display_name,status,analysis_mode,input_category,detected_category) VALUES(?,?,?,'fixture','ready','java_sca','binary','binary')`, task, actor, blob); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Exec(`DELETE FROM tasks WHERE id=?`, task); db.Exec(`DELETE FROM blobs WHERE id=?`, blob) })
	d := sbom.Document{Standard: "CycloneDX", SpecVersion: "1.6", Encoding: "json", InputSHA256: strings.Repeat("a", 64), Components: []sbom.Component{{Name: "commons-text", Version: "1.9", Group: "org.apache.commons", PURL: "pkg:maven/org.apache.commons/commons-text@1.9", SourceRef: "text", Path: "lib/text.jar"}}}
	if e = sbom.Finalize(&d); e != nil {
		t.Fatal(e)
	}
	if _, e = db.Exec(`INSERT INTO runs(id,kind,status,task_id,subject_type,subject_id,idempotency_key) VALUES(?,'sca_scan','complete',?,'task',?,'fixture')`, run, task, task); e != nil {
		t.Fatal(e)
	}
	tx, e := db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	inventory, e := PublishInventory(ctx, tx, task, run, d)
	if e != nil {
		t.Fatal(e)
	}
	findings := []Vulnerability{{ID: "CVE-2022-42889", ComponentID: d.Components[0].ID, Component: d.Components[0], Severity: "critical", Title: "fixture", Description: "from real scanner fixture"}}
	if e = PublishFindings(ctx, tx, task, run, inventory, d, findings); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	got, e := (Store{DB: db}).Occurrences(ctx, task, "", 100)
	if e != nil || len(got) != 1 || got[0].Status != "open" {
		t.Fatalf("%+v %v", got, e)
	}
	p, e := (impact.Store{DB: db}).SaveEnvironment(ctx, uint64(actor), "", 0, impact.Environment{Name: "Production", JavaRelease: 17, ApplicationType: "java", Facts: map[string]impact.Fact{}})
	if e != nil {
		t.Fatal(e)
	}
	q, e := (impact.Store{DB: db}).SaveEnvironment(ctx, uint64(actor), p.ProfileID, 1, impact.Environment{Name: "Production", JavaRelease: 21, ApplicationType: "java"})
	if e != nil || q.Revision != 2 {
		t.Fatalf("%+v %v", q, e)
	}
	if _, e = (impact.Store{DB: db}).SaveEnvironment(ctx, uint64(actor), p.ProfileID, 1, q.Config); e == nil {
		t.Fatal("stale environment edit accepted")
	}
	old, e := (impact.Store{DB: db}).Environment(ctx, p.ID)
	if e != nil || old.Config.JavaRelease != 17 {
		t.Fatal("old snapshot changed", e)
	}
	var count int
	if e = db.QueryRow(`SELECT COUNT(*) FROM occurrence_findings WHERE occurrence_id=?`, got[0].ID).Scan(&count); e != nil || count != 1 {
		t.Fatal(count, e)
	}
	policy, e := (impact.Store{DB: db}).SavePolicy(ctx, uint64(actor), task, impact.Policy{Mode: "automatic", ValidHours: 24, Reachability: true})
	if e != nil {
		t.Fatal(e)
	}
	queued, e := (impact.Store{DB: db}).Queue(ctx, uint64(actor), task, "analysis-fixture", impact.RunRequest{SCARunID: run, InventoryID: inventory, EnvironmentVersionID: q.ID, PolicyID: policy.ID})
	if e != nil {
		t.Fatal(e)
	}
	var raw []byte
	if e = db.QueryRow(`SELECT request FROM runs WHERE id=?`, queued.ID).Scan(&raw); e != nil {
		t.Fatal(e)
	}
	var request impact.RunRequest
	if e = json.Unmarshal(raw, &request); e != nil {
		t.Fatal(e)
	}
	bundle, e := impact.Rules()
	if e != nil {
		t.Fatal(e)
	}
	code := impact.CodeResult{State: "not_reachable", Complete: true, InputSHA256: d.InputSHA256, ViewDigest: sbom.Digest("view"), RuleID: bundle.Rules[0].ID}
	a := impact.Evaluate(got[0].ID, queued.ID, q, policy, bundle, &bundle.Rules[0], code, time.Now().UTC())
	if !a.Excluded {
		t.Fatal(a)
	}
	tx, e = db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	assessmentBody, _ := json.Marshal(a)
	if _, e = tx.Exec(`INSERT INTO vulnerability_assessments(id,occurrence_id,run_id,environment_version_id,policy_id,knowledge_digest,reachability,environment_applicability,attack_preconditions,details) VALUES(?,?,?,?,?,?,?,?,?,?)`, a.ID, a.OccurrenceID, a.RunID, a.EnvironmentVersionID, a.PolicyID, a.KnowledgeDigest, a.Reachability, a.Environment, a.Attack, assessmentBody); e != nil {
		t.Fatal(e)
	}
	if e = disposition.ApplyAutomatic(ctx, tx, a, policy.Config, request.Revisions[a.OccurrenceID], time.Now()); e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec(`UPDATE runs SET status='complete' WHERE id=?`, queued.ID); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	got, e = (Store{DB: db}).Occurrences(ctx, task, "", 100)
	if e != nil || got[0].Status != "ignored" {
		t.Fatalf("automatic ignore not persisted: %+v %v", got, e)
	}
	hold := time.Now().UTC().Add(time.Hour)
	restored, e := (disposition.Store{DB: db}).Change(ctx, task, a.OccurrenceID, "restore-fixture", uint64(actor), disposition.Change{EnvironmentVersionID: q.ID, Status: "open", Reason: "verify restored state", ExpectedRevision: got[0].Dispositions[0].Revision, OverrideUntil: &hold})
	if e != nil {
		t.Fatal(e)
	}
	tx, e = db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	if e = disposition.ApplyAutomatic(ctx, tx, a, policy.Config, request.Revisions[a.OccurrenceID], time.Now()); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	got, e = (Store{DB: db}).Occurrences(ctx, task, "", 100)
	if e != nil || got[0].Status != "open" || got[0].Dispositions[0].Revision != restored.Revision {
		t.Fatalf("stale worker overrode manual restore: %+v %v", got, e)
	}
}
