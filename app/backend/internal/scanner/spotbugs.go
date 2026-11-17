package scanner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode"

	"binaryscan.local/backend/internal/checkrules"
	"binaryscan.local/backend/internal/frameworks"
	"binaryscan.local/backend/internal/jvmarchive"
	"binaryscan.local/backend/internal/storage"
)

const (
	javaNullDereferenceRuleID = "java-null-dereference"
	spotBugsProtocol          = "spotbugs-v1"
	spotBugsVersion           = "4.10.4"
	spotBugsInputLimit        = 64 << 20
	spotBugsDiagnosticLimit   = 100
)

var (
	errSpotBugsBusy     = errors.New("bytecode checker returned HTTP 429")
	errSpotBugsLargeJAR = errors.New("JAR exceeds the 64 MiB bytecode analysis limit")
)

type spotBugsInput struct {
	blobID         sql.NullString
	detectedFormat sql.NullString
	logicalPath    sql.NullString
	storageKey     sql.NullString
	sizeBytes      sql.NullInt64
	sha256         []byte
}

type spotBugsFinding struct {
	Pattern                  string                `json:"pattern"`
	ClassName                string                `json:"className"`
	MethodName               string                `json:"methodName"`
	MethodDescriptor         string                `json:"methodDescriptor"`
	SourcePath               string                `json:"sourcePath,omitempty"`
	OriginalLine             *int                  `json:"originalLine,omitempty"`
	BytecodeOffset           *int                  `json:"bytecodeOffset,omitempty"`
	ReturnValueSource        *spotBugsReturnSource `json:"returnValueSource,omitempty"`
	NullSourceBytecodeOffset *int                  `json:"nullSourceBytecodeOffset,omitempty"`
	LocationRole             string                `json:"locationRole,omitempty"`
	Message                  string                `json:"message"`
	Priority                 int                   `json:"priority"`
}

type spotBugsReturnSource struct {
	ClassName        string `json:"className"`
	MethodName       string `json:"methodName"`
	MethodDescriptor string `json:"methodDescriptor"`
}

type spotBugsResponse struct {
	Version            string               `json:"version"`
	Format             string               `json:"format,omitempty"`
	Status             string               `json:"status"`
	SkipReason         string               `json:"skipReason,omitempty"`
	ToolVersion        string               `json:"toolVersion,omitempty"`
	Findings           []spotBugsFinding    `json:"findings"`
	Diagnostics        []string             `json:"diagnostics"`
	Scope              *jvmarchive.Scope    `json:"scope,omitempty"`
	SuppressedFindings []spotBugsSuppressed `json:"suppressedFindings,omitempty"`
	ModelSummary       map[string]any       `json:"modelSummary,omitempty"`
}

type spotBugsSuppressed struct {
	Finding spotBugsFinding `json:"finding"`
	Proof   map[string]any  `json:"proof"`
}

func (project checkerProject) spotBugsFormat() string {
	if project.language != "java" || project.sourceKind != "jvm" ||
		(project.selection != nil && !slices.Contains(project.selection.EnabledRuleIDs, javaNullDereferenceRuleID)) {
		return ""
	}
	return spotBugsFormat(project.input.detectedFormat.String)
}

func spotBugsFormat(detected string) string {
	switch detected {
	case "jar":
		return "jar"
	case "class", "java-class":
		return "class"
	default:
		return ""
	}
}

func (e *Executor) checkSpotBugs(ctx context.Context, client *http.Client, url string, input spotBugsInput, manifest storage.Manifest, format string, remaining int) spotBugsResponse {
	return e.checkSpotBugsWithFrameworks(ctx, client, url, input, manifest, format, remaining, nil)
}

func (e *Executor) checkSpotBugsWithFrameworks(ctx context.Context, client *http.Client, url string, input spotBugsInput, manifest storage.Manifest, format string, remaining int, snapshot *frameworks.Snapshot) spotBugsResponse {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	body, wireFormat, scope, cleanup, err := e.prepareSpotBugsInput(ctx, input, manifest, format)
	defer cleanup()
	if err == errSpotBugsLargeJAR {
		return spotBugsResponse{
			Version: spotBugsProtocol, Format: format, Status: "skipped", SkipReason: "input_too_large",
			Findings: []spotBugsFinding{}, Diagnostics: []string{"SpotBugs skipped: " + err.Error()},
		}
	}
	for err == nil {
		result, callErr := callSpotBugsWithFrameworks(ctx, client, url, wireFormat, body, snapshot)
		if callErr == nil {
			result.Format = format
			result.Scope = scope
			if scope != nil && len(scope.Diagnostics) > 0 {
				result.Status = "partial"
				result.Diagnostics = append(result.Diagnostics, scope.Diagnostics...)
			}
			result.validateFindings(remaining)
			return result
		}
		if callErr != errSpotBugsBusy {
			err = callErr
			break
		}
		// The shared Java Checker only starts one SpotBugs JVM at a time.
		select {
		case <-time.After(2 * time.Second):
		case <-ctx.Done():
			err = fmt.Errorf("waiting for the busy bytecode checker: %w", ctx.Err())
		}
	}
	return spotBugsResponse{
		Version: spotBugsProtocol, Format: format, Status: "partial", Findings: []spotBugsFinding{},
		Diagnostics: []string{"SpotBugs: " + err.Error()}, Scope: scope,
	}
}

func (e *Executor) prepareSpotBugsInput(ctx context.Context, input spotBugsInput, manifest storage.Manifest, format string) ([]byte, string, *jvmarchive.Scope, func(), error) {
	noop := func() {}
	if format != "jar" {
		body, err := e.readSpotBugsInput(input, manifest, format)
		return body, format, nil, noop, err
	}
	if !input.blobID.Valid || !input.storageKey.Valid || !input.logicalPath.Valid || !input.sizeBytes.Valid ||
		input.blobID.String != manifest.InputBlobID || len(input.sha256) != sha256.Size ||
		!strings.EqualFold(hex.EncodeToString(input.sha256), manifest.InputSHA256) {
		return nil, format, nil, noop, fmt.Errorf("original binary identity is unavailable or does not match the source project")
	}
	filename, err := e.blobPath(input.storageKey.String)
	if err != nil {
		return nil, format, nil, noop, fmt.Errorf("original binary is unavailable")
	}
	if err := jvmarchive.Verify(ctx, filename, input.sizeBytes.Int64, manifest.InputSHA256); err != nil {
		return nil, format, nil, noop, err
	}
	workRoot := e.cfg.Worker.WorkRoot
	if workRoot == "" {
		workRoot = os.TempDir()
	}
	absWorkRoot, err := filepath.Abs(workRoot)
	if err != nil {
		return nil, format, nil, noop, err
	}
	work, err := os.MkdirTemp(absWorkRoot, "bytecode-input-")
	if err != nil {
		return nil, format, nil, noop, err
	}
	cleanup := func() {
		if filepath.Dir(work) == absWorkRoot && strings.HasPrefix(filepath.Base(work), "bytecode-input-") {
			_ = os.RemoveAll(work)
		}
	}
	groups := jvmarchive.GroupsFromEnvironment()
	if manifest.JVMArchive != nil {
		if manifest.JVMArchive.Version != jvmarchive.Version || manifest.JVMArchive.InputSHA256 != manifest.InputSHA256 {
			return nil, format, nil, cleanup, fmt.Errorf("JVM archive scope does not match original binary")
		}
		groups = append([]string{}, manifest.JVMArchive.ApplicationGroups...)
	}
	prepared, err := jvmarchive.Prepare(ctx, filename, filepath.Join(work, "modules"), jvmarchive.Options{ExpectedSHA256: manifest.InputSHA256, ApplicationGroups: groups})
	if err != nil {
		return nil, format, nil, cleanup, err
	}
	if prepared == nil {
		body, err := e.readSpotBugsInput(input, manifest, format)
		return body, format, nil, cleanup, err
	}
	if manifest.JVMArchive != nil && !prepared.SameInputs(manifest.JVMArchive) {
		return nil, "bundle", &prepared.Scope, cleanup, fmt.Errorf("prepared JVM modules do not match the source project scope")
	}
	if manifest.JVMArchive == nil {
		prepared.Scope.Diagnostics = append(prepared.Scope.Diagnostics, "Source project predates module-aware decompilation; create a new decompile project to cover nested application sources")
	}
	bundle := filepath.Join(work, "analysis.zip")
	if err := prepared.Bundle(ctx, bundle); err != nil {
		return nil, "bundle", &prepared.Scope, cleanup, err
	}
	file, err := os.Open(bundle)
	if err != nil {
		return nil, "bundle", &prepared.Scope, cleanup, err
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, jvmarchive.MaxBundleBytes+1))
	if err == nil && int64(len(body)) > jvmarchive.MaxBundleBytes {
		err = fmt.Errorf("prepared bytecode bundle exceeds transport limit")
	}
	return body, "bundle", &prepared.Scope, cleanup, err
}

// Send exactly the bytes whose identity was verified against the original
// source project's manifest and the current blob record.
func (e *Executor) readSpotBugsInput(input spotBugsInput, manifest storage.Manifest, format string) ([]byte, error) {
	if !input.blobID.Valid || !input.storageKey.Valid || !input.logicalPath.Valid || !input.sizeBytes.Valid ||
		input.blobID.String != manifest.InputBlobID || len(input.sha256) != sha256.Size ||
		!strings.EqualFold(hex.EncodeToString(input.sha256), manifest.InputSHA256) {
		return nil, fmt.Errorf("original binary identity is unavailable or does not match the source project")
	}
	if input.sizeBytes.Int64 <= 0 || (format != "jar" && input.sizeBytes.Int64 > spotBugsInputLimit) {
		return nil, fmt.Errorf("original binary exceeds the supported size or is empty")
	}
	filename, err := e.blobPath(input.storageKey.String)
	if err != nil {
		return nil, fmt.Errorf("original binary is unavailable")
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("cannot open the original binary")
	}
	defer file.Close()
	if input.sizeBytes.Int64 > spotBugsInputLimit {
		if err := jvmarchive.Verify(context.Background(), filename, input.sizeBytes.Int64, manifest.InputSHA256); err != nil {
			return nil, err
		}
		return nil, errSpotBugsLargeJAR
	}
	body, err := io.ReadAll(io.LimitReader(file, input.sizeBytes.Int64+1))
	if err != nil {
		return nil, fmt.Errorf("cannot read the original binary")
	}
	digest := sha256.Sum256(body)
	if int64(len(body)) != input.sizeBytes.Int64 || !bytes.Equal(digest[:], input.sha256) {
		return nil, fmt.Errorf("original binary size or digest does not match its blob record")
	}
	detected, err := detectFile(filename, input.logicalPath.String)
	if err != nil || spotBugsFormat(detected) != format {
		return nil, fmt.Errorf("original binary does not match the expected %s format", format)
	}
	return body, nil
}

func callSpotBugs(ctx context.Context, client *http.Client, url, format string, body []byte) (spotBugsResponse, error) {
	return callSpotBugsWithFrameworks(ctx, client, url, format, body, nil)
}

func callSpotBugsWithFrameworks(ctx context.Context, client *http.Client, url, format string, body []byte, snapshot *frameworks.Snapshot) (spotBugsResponse, error) {
	url = checkrules.BaseURL(url) + "/v1/bytecode/check?format=" + format
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return spotBugsResponse{}, fmt.Errorf("cannot create the bytecode request")
	}
	request.Header.Set("Content-Type", "application/octet-stream")
	frameworkHeaderLimited := false
	if snapshot != nil {
		if err := validateFrameworkSnapshot(snapshot, snapshot.InputSHA256); err != nil {
			return spotBugsResponse{}, err
		}
		versions, err := json.Marshal(snapshot.Artifacts)
		if err != nil {
			return spotBugsResponse{}, fmt.Errorf("cannot encode framework evidence")
		}
		if len(versions) > 4096 {
			// Retain the original SpotBugs pass even when metadata cannot fit
			// safely in the header. No non-null suppression is enabled.
			frameworkHeaderLimited = true
			snapshot = nil
		} else {
			request.Header.Set("X-BinaryScan-Frameworks", string(versions))
			request.Header.Set("X-BinaryScan-Frameworks-SHA256", snapshot.Digest)
			request.Header.Set("X-BinaryScan-Input-SHA256", strings.ToLower(snapshot.InputSHA256))
		}
	}
	if len(body) > 1<<20 {
		request.Header.Set("Expect", "100-continue")
	}
	bytecodeClient := *client
	bytecodeClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := bytecodeClient.Do(request)
	if err != nil {
		return spotBugsResponse{}, fmt.Errorf("bytecode checker is unavailable or timed out")
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusTooManyRequests {
		return spotBugsResponse{}, errSpotBugsBusy
	}
	if response.StatusCode != http.StatusOK {
		return spotBugsResponse{}, fmt.Errorf("bytecode checker returned HTTP %d", response.StatusCode)
	}
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, checkerResponseBytes+1))
	if err != nil || len(responseBody) > checkerResponseBytes {
		return spotBugsResponse{}, fmt.Errorf("cannot read the bytecode response within the supported size")
	}
	var result spotBugsResponse
	if err := json.Unmarshal(responseBody, &result); err != nil || result.Version != spotBugsProtocol ||
		result.ToolVersion != spotBugsVersion || (result.Status != "complete" && result.Status != "partial") ||
		result.SkipReason != "" || result.Findings == nil || len(result.Findings) > checkerFindingLimit ||
		result.Diagnostics == nil || len(result.Diagnostics) > spotBugsDiagnosticLimit {
		return spotBugsResponse{}, fmt.Errorf("bytecode response violates %s", spotBugsProtocol)
	}
	if err := validateSuppressedBytecode(result, snapshot); err != nil {
		return spotBugsResponse{}, err
	}
	for index, diagnostic := range result.Diagnostics {
		if len(diagnostic) > 1024 || strings.ContainsRune(diagnostic, '\x00') {
			return spotBugsResponse{}, fmt.Errorf("bytecode response contains an invalid diagnostic")
		}
		result.Diagnostics[index] = "SpotBugs: " + diagnostic
	}
	if frameworkHeaderLimited {
		result.Status = "partial"
		result.Diagnostics = append(result.Diagnostics, "SpotBugs: framework metadata exceeds the header limit; bytecode analysis ran with non-null suppression disabled")
	}
	result.Format = format
	return result, nil
}

func validateSuppressedBytecode(result spotBugsResponse, snapshot *frameworks.Snapshot) error {
	if len(result.Findings)+len(result.SuppressedFindings) > checkerFindingLimit {
		return fmt.Errorf("bytecode raw findings exceed the supported limit")
	}
	modelDigest := ""
	if snapshot != nil {
		if err := validateFrameworkSnapshot(snapshot, snapshot.InputSHA256); err != nil {
			return err
		}
		digest := sha256.Sum256([]byte("framework-contracts-v1\n" + snapshot.Digest))
		modelDigest = hex.EncodeToString(digest[:])
	}
	for _, suppressed := range result.SuppressedFindings {
		proof := suppressed.Proof
		if snapshot == nil || !suppressed.Finding.valid() || len(proof) > 32 ||
			proof["frameworksSha256"] != snapshot.Digest || proof["inputSha256"] != strings.ToLower(snapshot.InputSHA256) ||
			proof["methodDescriptor"] != suppressed.Finding.MethodDescriptor {
			return fmt.Errorf("bytecode suppression is not bound to its original input and framework evidence")
		}
		if (proof["modelId"] != "hutool-5.8.27-null-predicate" && proof["modelId"] != "spring-6.1.8-yaml-properties-concrete") || proof["modelVersion"] != "framework-contracts-v1" {
			return fmt.Errorf("bytecode suppression has an unrecognized non-null proof model")
		}
		if proof["modelDigest"] != modelDigest || !suppressionVersionMatches(proof["modelId"], snapshot.Artifacts) {
			return fmt.Errorf("bytecode suppression does not match the pinned framework model")
		}
		for _, key := range []string{"targetClassSha256", "providerClassSha256", "modelDigest"} {
			value, ok := proof[key].(string)
			if !ok {
				return fmt.Errorf("bytecode suppression has no %s", key)
			}
			bytes, err := hex.DecodeString(value)
			if err != nil || len(bytes) != sha256.Size {
				return fmt.Errorf("bytecode suppression contains an invalid %s", key)
			}
		}
		for _, key := range []string{"modelId", "modelVersion", "callOwner", "callName", "callDescriptor"} {
			value, ok := proof[key].(string)
			if !ok || !validSpotBugsIdentity(value, 1024) {
				return fmt.Errorf("bytecode suppression contains an invalid %s", key)
			}
		}
		if suppressed.Finding.BytecodeOffset == nil || proof["bytecodeOffset"] != float64(*suppressed.Finding.BytecodeOffset) {
			return fmt.Errorf("bytecode suppression location does not match its original finding")
		}
	}
	if result.ModelSummary != nil || len(result.SuppressedFindings) > 0 {
		summary := result.ModelSummary
		if snapshot == nil || summary["version"] != "framework-contracts-v1" || summary["modelDigest"] != modelDigest ||
			summary["frameworksSha256"] != snapshot.Digest || summary["inputSha256"] != strings.ToLower(snapshot.InputSHA256) ||
			summary["rawFindingCount"] != float64(len(result.Findings)+len(result.SuppressedFindings)) ||
			summary["suppressedFindingCount"] != float64(len(result.SuppressedFindings)) || summary["retainedFindingCount"] != float64(len(result.Findings)) {
			return fmt.Errorf("bytecode framework summary does not match its original findings")
		}
		encoded, err := json.Marshal(summary["frameworks"])
		var versions map[string]string
		if err != nil || json.Unmarshal(encoded, &versions) != nil || versions == nil ||
			frameworks.ArtifactsDigest(versions) != snapshot.Digest {
			return fmt.Errorf("bytecode framework summary contains unpinned versions")
		}
	}
	if result.ModelSummary != nil {
		encoded, err := json.Marshal(result.ModelSummary)
		if err != nil || len(encoded) > 1<<20 {
			return fmt.Errorf("bytecode framework evidence exceeds the supported limit")
		}
	}
	return nil
}

func suppressionVersionMatches(model any, versions map[string]string) bool {
	switch model {
	case "hutool-5.8.27-null-predicate":
		core, all := versions["cn.hutool:hutool-core"], versions["cn.hutool:hutool-all"]
		return (core == "5.8.27" || all == "5.8.27") && (core == "" || core == "5.8.27") && (all == "" || all == "5.8.27")
	case "spring-6.1.8-yaml-properties-concrete":
		return versions["org.springframework:spring-beans"] == "6.1.8" && versions["org.springframework:spring-core"] == "6.1.8"
	}
	return false
}

func (response *spotBugsResponse) validateFindings(remaining int) {
	valid := response.Findings[:0]
	invalidCount := 0
	for _, finding := range response.Findings {
		if !finding.valid() {
			invalidCount++
			continue
		}
		valid = append(valid, finding)
	}
	if invalidCount > 0 {
		response.Status = "partial"
		response.Diagnostics = append(response.Diagnostics, fmt.Sprintf("SpotBugs: discarded %d invalid bytecode findings", invalidCount))
	}
	if len(valid) > remaining {
		valid = valid[:remaining]
		response.Status = "partial"
		response.Diagnostics = append(response.Diagnostics, "SpotBugs: findings exceeded the run finding limit")
	}
	response.Findings = valid
}

func (finding spotBugsFinding) valid() bool {
	switch finding.Pattern {
	case "NP_ALWAYS_NULL", "NP_ALWAYS_NULL_EXCEPTION", "NP_NULL_ON_SOME_PATH", "NP_NULL_ON_SOME_PATH_EXCEPTION",
		"NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE", "NP_GUARANTEED_DEREF", "NP_GUARANTEED_DEREF_ON_EXCEPTION_PATH", "NP_CLOSING_NULL":
	default:
		return false
	}
	if !validSpotBugsIdentity(finding.ClassName, 1024) || strings.ContainsAny(finding.ClassName, "/\\:") ||
		!validSpotBugsIdentity(finding.MethodName, 512) || !validSpotBugsIdentity(finding.MethodDescriptor, 1024) ||
		!strings.HasPrefix(finding.MethodDescriptor, "(") || !strings.Contains(finding.MethodDescriptor, ")") ||
		utf16CodeUnitCount(finding.Message) > 4096 || strings.TrimSpace(finding.Message) == "" || strings.ContainsRune(finding.Message, '\x00') ||
		finding.Priority < 1 || finding.Priority > 3 || (finding.OriginalLine != nil && *finding.OriginalLine <= 0) ||
		(finding.BytecodeOffset != nil && *finding.BytecodeOffset < 0) ||
		(finding.NullSourceBytecodeOffset != nil && *finding.NullSourceBytecodeOffset < 0) ||
		(finding.LocationRole != "" && !validSpotBugsIdentity(finding.LocationRole, 128)) {
		return false
	}
	if source := finding.ReturnValueSource; source != nil {
		if !validSpotBugsIdentity(source.ClassName, 1024) || strings.ContainsAny(source.ClassName, "/\\:") ||
			!validSpotBugsIdentity(source.MethodName, 512) || !validSpotBugsIdentity(source.MethodDescriptor, 1024) ||
			!strings.HasPrefix(source.MethodDescriptor, "(") || !strings.Contains(source.MethodDescriptor, ")") {
			return false
		}
	}
	if finding.SourcePath != "" {
		cleaned, err := storage.CleanRelativePath(finding.SourcePath)
		return err == nil && cleaned == finding.SourcePath && !strings.ContainsRune(cleaned, ':')
	}
	return true
}

func validSpotBugsIdentity(value string, limit int) bool {
	return value != "" && utf16CodeUnitCount(value) <= limit && value == strings.TrimSpace(value) &&
		strings.IndexFunc(value, unicode.IsControl) < 0
}

func (finding spotBugsFinding) evidence(version string) map[string]any {
	evidence := map[string]any{
		"engine": "spotbugs", "locationKind": "bytecode", "pattern": finding.Pattern, "className": finding.ClassName,
		"methodName": finding.MethodName, "methodDescriptor": finding.MethodDescriptor, "toolVersion": version,
		"priority": finding.Priority,
	}
	if finding.SourcePath != "" {
		evidence["sourcePath"] = finding.SourcePath
	}
	if finding.OriginalLine != nil {
		evidence["originalLine"] = *finding.OriginalLine
	}
	if finding.BytecodeOffset != nil {
		evidence["bytecodeOffset"] = *finding.BytecodeOffset
	}
	if finding.ReturnValueSource != nil {
		evidence["returnValueSource"] = finding.ReturnValueSource
	}
	if finding.NullSourceBytecodeOffset != nil {
		evidence["nullSourceBytecodeOffset"] = *finding.NullSourceBytecodeOffset
	}
	if finding.LocationRole != "" {
		evidence["locationRole"] = finding.LocationRole
	}
	return evidence
}
