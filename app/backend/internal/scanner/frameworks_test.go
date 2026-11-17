package scanner

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"binaryscan.local/backend/internal/checkrules"
	"binaryscan.local/backend/internal/config"
	"binaryscan.local/backend/internal/frameworks"
	"binaryscan.local/backend/internal/storage"
)

func frameworkJar(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var body bytes.Buffer
	writer := zip.NewWriter(&body)
	for name, content := range entries {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return body.Bytes()
}

func frameworkOriginal(t *testing.T, body []byte) (Executor, checkerProject, storage.Manifest) {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "original.jar"), body, 0600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	manifestHash := sha256.Sum256([]byte("frozen source manifest"))
	project := checkerProject{id: "project", language: "java", sourceKind: "jvm", manifestSHA256: manifestHash[:], input: spotBugsInput{
		blobID: sql.NullString{String: "original-blob", Valid: true}, storageKey: sql.NullString{String: "original.jar", Valid: true},
		logicalPath: sql.NullString{String: "renamed-input.jar", Valid: true}, sizeBytes: sql.NullInt64{Int64: int64(len(body)), Valid: true}, sha256: digest[:],
	}}
	manifest := storage.Manifest{InputBlobID: "original-blob", InputSHA256: hex.EncodeToString(digest[:]), Quality: "source", Files: []storage.ManifestFile{{Path: "application/Demo.java", Language: "java", SizeBytes: 10, SHA256: strings.Repeat("d", 64)}}}
	return Executor{cfg: config.Config{Worker: config.Worker{BlobRoot: root}}}, project, manifest
}

func TestFrameworkOriginalEvidenceIsBoundToBlobAndSourceManifest(t *testing.T) {
	body := frameworkJar(t, map[string][]byte{"META-INF/maven/cn.hutool/hutool-core/pom.properties": []byte("groupId=cn.hutool\nartifactId=hutool-core\nversion=5.8.27\n")})
	executor, project, manifest := frameworkOriginal(t, body)
	snapshot, err := executor.detectJavaFrameworks(context.Background(), project, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.InputSHA256 != manifest.InputSHA256 || snapshot.Artifacts["cn.hutool:hutool-core"] != "5.8.27" || snapshot.Digest != frameworks.ArtifactsDigest(snapshot.Artifacts) {
		t.Fatalf("unbound framework identity: %+v", snapshot)
	}
	for name, change := range map[string]func(*checkerProject, *storage.Manifest){
		"source blob mismatch":   func(p *checkerProject, m *storage.Manifest) { m.InputBlobID = "another-blob" },
		"source digest mismatch": func(p *checkerProject, m *storage.Manifest) { m.InputSHA256 = strings.Repeat("0", 64) },
		"blob digest mismatch":   func(p *checkerProject, m *storage.Manifest) { p.input.sha256 = make([]byte, sha256.Size) },
		"blob size mismatch":     func(p *checkerProject, m *storage.Manifest) { p.input.sizeBytes.Int64++ },
		"missing blob identity":  func(p *checkerProject, m *storage.Manifest) { p.input.blobID.Valid = false },
		"unsafe blob key":        func(p *checkerProject, m *storage.Manifest) { p.input.storageKey.String = "../other.jar" },
	} {
		t.Run(name, func(t *testing.T) {
			p, m := project, manifest
			change(&p, &m)
			if _, err := executor.detectJavaFrameworks(context.Background(), p, m); err == nil {
				t.Fatal("accepted unbound framework evidence")
			}
		})
	}
	// Same-size disk mutation must not pass using the database's old digest.
	mutated := bytes.Clone(body)
	mutated[len(mutated)/2] ^= 1
	if err := os.WriteFile(filepath.Join(executor.cfg.Worker.BlobRoot, "original.jar"), mutated, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := executor.detectJavaFrameworks(context.Background(), project, manifest); err == nil {
		t.Fatal("mutated original accepted")
	}
}

func frameworkSelection(t *testing.T) *checkrules.Selection {
	t.Helper()
	catalog := checkrules.Catalog{Version: "checker-v1", Language: "java", CatalogVersion: "sha256:" + strings.Repeat("a", 64), Rules: []checkrules.Rule{{ID: javaNullDereferenceRuleID, Name: "Null dereference", Language: "java"}}}
	selection, err := checkrules.Select(catalog, []string{javaNullDereferenceRuleID}, catalog.CatalogVersion, false)
	if err != nil {
		t.Fatal(err)
	}
	return selection
}

func TestFrameworkProjectRequestPinsExactEvidenceAndConflicts(t *testing.T) {
	one := frameworkJar(t, map[string][]byte{"META-INF/maven/cn.hutool/hutool-core/pom.properties": []byte("groupId=cn.hutool\nartifactId=hutool-core\nversion=5.8.27\n")})
	two := frameworkJar(t, map[string][]byte{"META-INF/maven/cn.hutool/hutool-core/pom.properties": []byte("groupId=cn.hutool\nartifactId=hutool-core\nversion=5.8.28\n")})
	executor, project, manifest := frameworkOriginal(t, frameworkJar(t, map[string][]byte{"BOOT-INF/lib/one.jar": one, "BOOT-INF/lib/two.jar": two}))
	snapshot, err := executor.detectJavaFrameworks(context.Background(), project, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Conflicts) != 1 || len(snapshot.Artifacts) != 0 {
		t.Fatalf("conflict did not disable coordinate: %+v", snapshot)
	}
	project.frameworks = &snapshot
	project.selection = frameworkSelection(t)
	var received struct {
		ProjectID, RunID, ManifestSHA256, InputSHA256, FrameworksSHA256 string
		Frameworks                                                      map[string]string
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
				t.Error(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"version": javaProjectProtocol, "sessionId": strings.Repeat("a", 32)})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	session, err := createJavaProject(context.Background(), server.Client(), server.URL+"/v1/check", project, manifest, "run")
	if err != nil {
		t.Fatal(err)
	}
	session.close()
	if received.ProjectID != "project" || received.RunID != "run" || received.InputSHA256 != manifest.InputSHA256 || received.ManifestSHA256 != hex.EncodeToString(project.manifestSHA256) || received.FrameworksSHA256 != snapshot.Digest || len(received.Frameworks) != 0 {
		t.Fatalf("request lost pinned identity or reactivated conflict: %+v", received)
	}
	summary := javaAnalysisSummary(manifest, nil, []string{"Java framework metadata contains conflicting versions; affected non-null contracts were disabled"}, spotBugsResponse{}, true)
	if summary["engines"].(map[string]any)["source"].(map[string]any)["status"] != "partial" {
		t.Fatal("framework conflict falsely represented as complete")
	}
}

func TestFrameworkProjectRejectsMismatchedSnapshotBeforeTransport(t *testing.T) {
	executor, project, manifest := frameworkOriginal(t, []byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 61})
	snapshot, err := executor.detectJavaFrameworks(context.Background(), project, manifest)
	if err != nil {
		t.Fatal(err)
	}
	project.selection = frameworkSelection(t)
	for name, mutate := range map[string]func(*frameworks.Snapshot){
		"wrong original": func(s *frameworks.Snapshot) { s.InputSHA256 = strings.Repeat("f", 64) },
		"wrong digest":   func(s *frameworks.Snapshot) { s.Digest = strings.Repeat("f", 64) },
		"wrong version":  func(s *frameworks.Snapshot) { s.Version = "framework-evidence-v0" },
		"conflict still enabled": func(s *frameworks.Snapshot) {
			s.Artifacts = map[string]string{"cn.hutool:hutool-core": "5.8.27"}
			s.Digest = frameworks.ArtifactsDigest(s.Artifacts)
			s.Conflicts = []frameworks.Conflict{{Coordinate: "cn.hutool:hutool-core", Versions: []string{"5.8.27", "5.8.28"}}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := snapshot
			mutate(&candidate)
			p := project
			p.frameworks = &candidate
			called := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				_ = json.NewEncoder(w).Encode(map[string]string{"version": javaProjectProtocol, "sessionId": strings.Repeat("a", 32)})
			}))
			defer server.Close()
			if _, err := createJavaProject(context.Background(), server.Client(), server.URL, p, manifest, "run"); err == nil || called {
				t.Fatalf("unbound framework snapshot crossed transport: err=%v called=%v", err, called)
			}
		})
	}
}

func frameworkSuppressionFixture() (spotBugsResponse, *frameworks.Snapshot) {
	snapshot := frameworks.Empty(strings.Repeat("c", 64))
	snapshot.Artifacts = map[string]string{"cn.hutool:hutool-core": "5.8.27"}
	snapshot.Digest = frameworks.ArtifactsDigest(snapshot.Artifacts)
	modelDigest := sha256.Sum256([]byte("framework-contracts-v1\n" + snapshot.Digest))
	offset := 3
	finding := spotBugsFinding{Pattern: "NP_NULL_ON_SOME_PATH", ClassName: "sample.Demo", MethodName: "length", MethodDescriptor: "(Ljava/lang/String;)I", BytecodeOffset: &offset, Message: "Possible null pointer dereference", Priority: 1, LocationRole: "SOURCE_LINE_DEREF"}
	proof := map[string]any{"modelId": "hutool-5.8.27-null-predicate", "modelVersion": "framework-contracts-v1", "modelDigest": hex.EncodeToString(modelDigest[:]), "frameworksSha256": snapshot.Digest, "inputSha256": snapshot.InputSHA256,
		"targetClassSha256": strings.Repeat("a", 64), "providerClassSha256": strings.Repeat("b", 64), "providerClassName": "cn/hutool/core/util/ObjectUtil", "methodDescriptor": finding.MethodDescriptor, "bytecodeOffset": float64(offset), "callOwner": "cn/hutool/core/util/ObjectUtil", "callName": "isNull", "callDescriptor": "(Ljava/lang/Object;)Z"}
	result := spotBugsResponse{Version: spotBugsProtocol, Status: "complete", ToolVersion: spotBugsVersion, Findings: []spotBugsFinding{}, Diagnostics: []string{}, SuppressedFindings: []spotBugsSuppressed{{Finding: finding, Proof: proof}}, ModelSummary: map[string]any{
		"version": "framework-contracts-v1", "modelDigest": hex.EncodeToString(modelDigest[:]), "frameworksSha256": snapshot.Digest, "inputSha256": snapshot.InputSHA256, "frameworks": snapshot.Artifacts,
		"rawFindingCount": float64(1), "suppressedFindingCount": float64(1), "retainedFindingCount": float64(0),
	}}
	return result, &snapshot
}

func TestFrameworkBytecodeAcceptsBoundProofAndTransmitsFrozenHeaders(t *testing.T) {
	result, snapshot := frameworkSuppressionFixture()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-BinaryScan-Frameworks-SHA256") != snapshot.Digest || r.Header.Get("X-BinaryScan-Input-SHA256") != snapshot.InputSHA256 {
			t.Error("original framework identity not transmitted")
		}
		var versions map[string]string
		if err := json.Unmarshal([]byte(r.Header.Get("X-BinaryScan-Frameworks")), &versions); err != nil || versions["cn.hutool:hutool-core"] != "5.8.27" {
			t.Errorf("wrong versions: %v %v", versions, err)
		}
		_ = json.NewEncoder(w).Encode(result)
	}))
	defer server.Close()
	accepted, err := callSpotBugsWithFrameworks(context.Background(), server.Client(), server.URL, "jar", []byte("already-verified-wire-input"), snapshot)
	if err != nil || len(accepted.SuppressedFindings) != 1 || len(accepted.Findings) != 0 {
		t.Fatalf("valid suppression rejected: %+v %v", accepted, err)
	}
}

func TestFrameworkBytecodeRejectsUnboundOrInventedSuppression(t *testing.T) {
	for name, mutate := range map[string]func(*spotBugsResponse, **frameworks.Snapshot){
		"missing snapshot": func(r *spotBugsResponse, s **frameworks.Snapshot) { *s = nil },
		"wrong proof input": func(r *spotBugsResponse, s **frameworks.Snapshot) {
			r.SuppressedFindings[0].Proof["inputSha256"] = strings.Repeat("f", 64)
		},
		"wrong proof frameworks": func(r *spotBugsResponse, s **frameworks.Snapshot) {
			r.SuppressedFindings[0].Proof["frameworksSha256"] = strings.Repeat("f", 64)
		},
		"wrong proof model digest": func(r *spotBugsResponse, s **frameworks.Snapshot) {
			r.SuppressedFindings[0].Proof["modelDigest"] = strings.Repeat("f", 64)
		},
		"wrong bytecode offset": func(r *spotBugsResponse, s **frameworks.Snapshot) {
			r.SuppressedFindings[0].Proof["bytecodeOffset"] = float64(9)
		},
		"missing bytecode offset": func(r *spotBugsResponse, s **frameworks.Snapshot) {
			r.SuppressedFindings[0].Finding.BytecodeOffset = nil
		},
		"wrong method descriptor": func(r *spotBugsResponse, s **frameworks.Snapshot) {
			r.SuppressedFindings[0].Proof["methodDescriptor"] = "()V"
		},
		"unknown model": func(r *spotBugsResponse, s **frameworks.Snapshot) {
			r.SuppressedFindings[0].Proof["modelId"] = "blanket-ignore-null"
		},
		"wrong model version": func(r *spotBugsResponse, s **frameworks.Snapshot) {
			r.SuppressedFindings[0].Proof["modelVersion"] = "framework-contracts-v0"
		},
		"invalid target class digest": func(r *spotBugsResponse, s **frameworks.Snapshot) {
			r.SuppressedFindings[0].Proof["targetClassSha256"] = "not-a-hash"
		},
		"missing provider digest": func(r *spotBugsResponse, s **frameworks.Snapshot) {
			delete(r.SuppressedFindings[0].Proof, "providerClassSha256")
		},
		"missing summary": func(r *spotBugsResponse, s **frameworks.Snapshot) { r.ModelSummary = nil },
		"wrong summary input": func(r *spotBugsResponse, s **frameworks.Snapshot) {
			r.ModelSummary["inputSha256"] = strings.Repeat("f", 64)
		},
		"wrong summary frameworks": func(r *spotBugsResponse, s **frameworks.Snapshot) {
			r.ModelSummary["frameworksSha256"] = strings.Repeat("f", 64)
		},
		"wrong summary version map": func(r *spotBugsResponse, s **frameworks.Snapshot) {
			r.ModelSummary["frameworks"] = map[string]string{"cn.hutool:hutool-core": "5.8.28"}
		},
		"missing summary version map": func(r *spotBugsResponse, s **frameworks.Snapshot) {
			delete(r.ModelSummary, "frameworks")
		},
		"invalid summary version map": func(r *spotBugsResponse, s **frameworks.Snapshot) {
			r.ModelSummary["frameworks"] = []string{"hutool-5.8.27"}
		},
		"wrong summary version": func(r *spotBugsResponse, s **frameworks.Snapshot) { r.ModelSummary["version"] = "old-models" },
		"wrong summary model digest": func(r *spotBugsResponse, s **frameworks.Snapshot) {
			r.ModelSummary["modelDigest"] = strings.Repeat("f", 64)
		},
		"wrong raw count": func(r *spotBugsResponse, s **frameworks.Snapshot) { r.ModelSummary["rawFindingCount"] = float64(2) },
		"wrong suppressed count": func(r *spotBugsResponse, s **frameworks.Snapshot) {
			r.ModelSummary["suppressedFindingCount"] = float64(0)
		},
		"wrong retained count": func(r *spotBugsResponse, s **frameworks.Snapshot) {
			r.ModelSummary["retainedFindingCount"] = float64(1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			result, snapshot := frameworkSuppressionFixture()
			mutate(&result, &snapshot)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(result) }))
			defer server.Close()
			if _, err := callSpotBugsWithFrameworks(context.Background(), server.Client(), server.URL, "jar", nil, snapshot); err == nil {
				t.Fatal("unbound non-null proof accepted")
			}
		})
	}
}

func TestFrameworkBytecodeRequiresModelSpecificVerifiedVersions(t *testing.T) {
	for name, artifacts := range map[string]map[string]string{
		"framework absent":         {},
		"wrong hutool version":     {"cn.hutool:hutool-core": "5.8.28"},
		"conflicting core and all": {"cn.hutool:hutool-core": "5.8.27", "cn.hutool:hutool-all": "5.8.28"},
	} {
		t.Run(name, func(t *testing.T) {
			result, snapshot := frameworkSuppressionFixture()
			snapshot.Artifacts = artifacts
			snapshot.Digest = frameworks.ArtifactsDigest(artifacts)
			modelDigest := sha256.Sum256([]byte("framework-contracts-v1\n" + snapshot.Digest))
			result.SuppressedFindings[0].Proof["frameworksSha256"] = snapshot.Digest
			result.SuppressedFindings[0].Proof["modelDigest"] = hex.EncodeToString(modelDigest[:])
			result.ModelSummary["frameworksSha256"] = snapshot.Digest
			result.ModelSummary["modelDigest"] = hex.EncodeToString(modelDigest[:])
			result.ModelSummary["frameworks"] = artifacts
			if err := validateSuppressedBytecode(result, snapshot); err == nil {
				t.Fatal("model applied without its exact verified dependency versions")
			}
		})
	}
	result, snapshot := frameworkSuppressionFixture()
	snapshot.Digest = strings.Repeat("f", 64)
	result.SuppressedFindings[0].Proof["frameworksSha256"] = snapshot.Digest
	result.ModelSummary["frameworksSha256"] = snapshot.Digest
	if err := validateSuppressedBytecode(result, snapshot); err == nil {
		t.Fatal("snapshot map and fingerprint disagree")
	}
}

func TestFrameworkBytecodeKeepsLegacyResultsWithoutAnySuppression(t *testing.T) {
	result, _ := frameworkSuppressionFixture()
	result.SuppressedFindings = nil
	result.ModelSummary = nil
	if err := validateSuppressedBytecode(result, nil); err != nil {
		t.Fatalf("legacy unsuppressed result rejected: %v", err)
	}
}

func rebindFrameworkSuppression(result *spotBugsResponse, snapshot *frameworks.Snapshot, versions map[string]string) {
	snapshot.Artifacts = versions
	snapshot.Digest = frameworks.ArtifactsDigest(versions)
	digest := sha256.Sum256([]byte("framework-contracts-v1\n" + snapshot.Digest))
	result.ModelSummary["frameworks"] = versions
	result.ModelSummary["frameworksSha256"] = snapshot.Digest
	result.ModelSummary["modelDigest"] = hex.EncodeToString(digest[:])
	for _, suppressed := range result.SuppressedFindings {
		suppressed.Proof["frameworksSha256"] = snapshot.Digest
		suppressed.Proof["modelDigest"] = hex.EncodeToString(digest[:])
	}
}

func TestFrameworkBytecodeAcceptsApprovedAllArtifactAndSpringVersions(t *testing.T) {
	for name, versions := range map[string]map[string]string{
		"hutool all exact": {"cn.hutool:hutool-all": "5.8.27"},
		"spring exact":     {"org.springframework:spring-beans": "6.1.8", "org.springframework:spring-core": "6.1.8"},
	} {
		t.Run(name, func(t *testing.T) {
			result, snapshot := frameworkSuppressionFixture()
			rebindFrameworkSuppression(&result, snapshot, versions)
			if strings.HasPrefix(name, "spring") {
				proof := result.SuppressedFindings[0].Proof
				proof["modelId"] = "spring-6.1.8-yaml-properties-concrete"
				proof["callOwner"] = "org/springframework/beans/factory/config/YamlPropertiesFactoryBean"
				proof["callName"] = "getObject"
				proof["callDescriptor"] = "()Ljava/util/Properties;"
				proof["providerClassName"] = proof["callOwner"]
			}
			if err := validateSuppressedBytecode(result, snapshot); err != nil {
				t.Fatalf("exact verified model rejected: %v", err)
			}
		})
	}
	for name, versions := range map[string]map[string]string{
		"missing spring core": {"org.springframework:spring-beans": "6.1.8"},
		"wrong spring core":   {"org.springframework:spring-beans": "6.1.8", "org.springframework:spring-core": "6.1.9"},
		"wrong spring beans":  {"org.springframework:spring-beans": "6.1.9", "org.springframework:spring-core": "6.1.8"},
	} {
		t.Run(name, func(t *testing.T) {
			result, snapshot := frameworkSuppressionFixture()
			rebindFrameworkSuppression(&result, snapshot, versions)
			result.SuppressedFindings[0].Proof["modelId"] = "spring-6.1.8-yaml-properties-concrete"
			if err := validateSuppressedBytecode(result, snapshot); err == nil {
				t.Fatal("Spring model applied outside its exact verified dependencies")
			}
		})
	}
}

func TestFrameworkBytecodeValidatesSummaryEvenWithoutSuppression(t *testing.T) {
	for name, mutate := range map[string]func(*spotBugsResponse, **frameworks.Snapshot){
		"summary without snapshot": func(r *spotBugsResponse, s **frameworks.Snapshot) { *s = nil },
		"unbound empty summary": func(r *spotBugsResponse, s **frameworks.Snapshot) {
			r.ModelSummary["inputSha256"] = strings.Repeat("f", 64)
		},
		"invented raw count": func(r *spotBugsResponse, s **frameworks.Snapshot) { r.ModelSummary["rawFindingCount"] = float64(100) },
		"invented retained count": func(r *spotBugsResponse, s **frameworks.Snapshot) {
			r.ModelSummary["retainedFindingCount"] = float64(100)
		},
	} {
		t.Run(name, func(t *testing.T) {
			result, snapshot := frameworkSuppressionFixture()
			result.SuppressedFindings = nil
			result.ModelSummary["rawFindingCount"] = float64(0)
			result.ModelSummary["suppressedFindingCount"] = float64(0)
			result.ModelSummary["retainedFindingCount"] = float64(0)
			mutate(&result, &snapshot)
			if err := validateSuppressedBytecode(result, snapshot); err == nil {
				t.Fatal("unbound or fabricated framework audit summary accepted")
			}
		})
	}
	result, snapshot := frameworkSuppressionFixture()
	result.SuppressedFindings = nil
	result.ModelSummary["rawFindingCount"] = float64(0)
	result.ModelSummary["suppressedFindingCount"] = float64(0)
	result.ModelSummary["retainedFindingCount"] = float64(0)
	if err := validateSuppressedBytecode(result, snapshot); err != nil {
		t.Fatalf("bound empty audit summary rejected: %v", err)
	}
}

func TestFrameworkOversizedHeaderPreservesOriginalBytecodeResults(t *testing.T) {
	result, snapshot := frameworkSuppressionFixture()
	finding := result.SuppressedFindings[0].Finding
	result.SuppressedFindings = nil
	result.ModelSummary = nil
	result.Findings = []spotBugsFinding{finding}
	for index := 0; index < 100; index++ {
		snapshot.Artifacts[fmt.Sprintf("test.framework:artifact-%03d", index)] = strings.Repeat("1", 64)
	}
	snapshot.Digest = frameworks.ArtifactsDigest(snapshot.Artifacts)
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		for _, name := range []string{"X-BinaryScan-Frameworks", "X-BinaryScan-Frameworks-SHA256", "X-BinaryScan-Input-SHA256"} {
			if r.Header.Get(name) != "" {
				t.Errorf("oversized metadata should disable all non-null contracts: %s", name)
			}
		}
		_ = json.NewEncoder(w).Encode(result)
	}))
	defer server.Close()
	accepted, err := callSpotBugsWithFrameworks(context.Background(), server.Client(), server.URL, "jar", nil, snapshot)
	if err != nil || !called || accepted.Status != "partial" || len(accepted.Findings) != 1 || len(accepted.SuppressedFindings) != 0 {
		t.Fatalf("lost original findings during safe header degradation: %+v %v", accepted, err)
	}
	if !strings.Contains(strings.Join(accepted.Diagnostics, " "), "suppression disabled") {
		t.Fatal("degradation reason missing")
	}
}

func TestFrameworkSourceModelSummaryKeepsVerifiableLocationsAndDigest(t *testing.T) {
	_, snapshot := frameworkSuppressionFixture()
	sources := map[string]checkerSourceEvidence{"application/Foo.java": {lines: []string{"Object value = factory();"}}}
	fixture := func() map[string]any {
		digest := sha256.Sum256([]byte("framework-contracts-v1\n" + snapshot.Digest))
		return map[string]any{"modelVersion": "java-nullness-v4", "frameworkContractVersion": "framework-contracts-v1", "frameworkContractDigest": hex.EncodeToString(digest[:]),
			"proofs": []map[string]any{{"path": "application/Foo.java", "line": 1, "column": 1, "modelId": "hutool-5.8.27-container", "condition": "normal return creates a non-null collection", "dependencyVersion": "5.8.27"}}, "proofsTruncated": false}
	}
	if !verifyJavaModelSummary(fixture(), snapshot, sources) {
		t.Fatal("verified model summary rejected")
	}
	for name, mutate := range map[string]func(map[string]any){
		"wrong digest":             func(s map[string]any) { s["frameworkContractDigest"] = strings.Repeat("f", 64) },
		"unknown model version":    func(s map[string]any) { s["modelVersion"] = "java-nullness-old" },
		"unknown contract version": func(s map[string]any) { s["frameworkContractVersion"] = "framework-contracts-old" },
		"unknown file":             func(s map[string]any) { s["proofs"].([]map[string]any)[0]["path"] = "other/Foo.java" },
		"unsafe file":              func(s map[string]any) { s["proofs"].([]map[string]any)[0]["path"] = "../outside.java" },
		"out of range line":        func(s map[string]any) { s["proofs"].([]map[string]any)[0]["line"] = 20 },
		"out of range column":      func(s map[string]any) { s["proofs"].([]map[string]any)[0]["column"] = 1000 },
		"missing model id":         func(s map[string]any) { delete(s["proofs"].([]map[string]any)[0], "modelId") },
		"unknown truncation":       func(s map[string]any) { delete(s, "proofsTruncated") },
	} {
		t.Run(name, func(t *testing.T) {
			summary := fixture()
			mutate(summary)
			if verifyJavaModelSummary(summary, snapshot, sources) {
				t.Fatal("unverifiable source model evidence accepted")
			}
		})
	}
	summary := fixture()
	summary["proofs"].([]map[string]any)[0]["column"] = 2
	sources["application/Foo.java"] = checkerSourceEvidence{lines: []string{"😀Object value;"}}
	if verifyJavaModelSummary(summary, snapshot, sources) {
		t.Fatal("UTF-16 surrogate midpoint accepted")
	}
	if !verifyJavaModelSummary(nil, nil, sources) {
		t.Fatal("legacy source response without model claims rejected")
	}
}
