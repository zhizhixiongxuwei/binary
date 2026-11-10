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
	"slices"
	"strings"
	"time"
	"unicode"

	"binaryscan.local/backend/internal/checkrules"
	"binaryscan.local/backend/internal/storage"
)

const (
	javaNullDereferenceRuleID = "java-null-dereference"
	spotBugsProtocol          = "spotbugs-v1"
	spotBugsVersion           = "4.10.4"
	spotBugsInputLimit        = 64 << 20
	spotBugsDiagnosticLimit   = 100
)

var errSpotBugsBusy = errors.New("bytecode checker returned HTTP 429")

type spotBugsInput struct {
	blobID         sql.NullString
	detectedFormat sql.NullString
	logicalPath    sql.NullString
	storageKey     sql.NullString
	sizeBytes      sql.NullInt64
	sha256         []byte
}

type spotBugsFinding struct {
	Pattern          string `json:"pattern"`
	ClassName        string `json:"className"`
	MethodName       string `json:"methodName"`
	MethodDescriptor string `json:"methodDescriptor"`
	SourcePath       string `json:"sourcePath,omitempty"`
	OriginalLine     *int   `json:"originalLine,omitempty"`
	BytecodeOffset   *int   `json:"bytecodeOffset,omitempty"`
	LocationRole     string `json:"locationRole,omitempty"`
	Message          string `json:"message"`
	Priority         int    `json:"priority"`
}

type spotBugsResponse struct {
	Version     string            `json:"version"`
	Format      string            `json:"format,omitempty"`
	Status      string            `json:"status"`
	ToolVersion string            `json:"toolVersion,omitempty"`
	Findings    []spotBugsFinding `json:"findings"`
	Diagnostics []string          `json:"diagnostics"`
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
	ctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	body, err := e.readSpotBugsInput(input, manifest, format)
	for err == nil {
		result, callErr := callSpotBugs(ctx, client, url, format, body)
		if callErr == nil {
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
		Diagnostics: []string{"SpotBugs: " + err.Error()},
	}
}

// Send exactly the bytes whose identity was verified against the original
// source project's manifest and the current blob record.
func (e *Executor) readSpotBugsInput(input spotBugsInput, manifest storage.Manifest, format string) ([]byte, error) {
	if !input.blobID.Valid || !input.storageKey.Valid || !input.logicalPath.Valid || !input.sizeBytes.Valid ||
		input.blobID.String != manifest.InputBlobID || len(input.sha256) != sha256.Size ||
		!strings.EqualFold(hex.EncodeToString(input.sha256), manifest.InputSHA256) {
		return nil, fmt.Errorf("original binary identity is unavailable or does not match the source project")
	}
	if input.sizeBytes.Int64 <= 0 || input.sizeBytes.Int64 > spotBugsInputLimit {
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
	url = checkrules.BaseURL(url) + "/v1/bytecode/check?format=" + format
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return spotBugsResponse{}, fmt.Errorf("cannot create the bytecode request")
	}
	request.Header.Set("Content-Type", "application/octet-stream")
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
		result.Findings == nil || len(result.Findings) > checkerFindingLimit ||
		result.Diagnostics == nil || len(result.Diagnostics) > spotBugsDiagnosticLimit {
		return spotBugsResponse{}, fmt.Errorf("bytecode response violates %s", spotBugsProtocol)
	}
	for index, diagnostic := range result.Diagnostics {
		if len(diagnostic) > 1024 || strings.ContainsRune(diagnostic, '\x00') {
			return spotBugsResponse{}, fmt.Errorf("bytecode response contains an invalid diagnostic")
		}
		result.Diagnostics[index] = "SpotBugs: " + diagnostic
	}
	result.Format = format
	return result, nil
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
		(finding.LocationRole != "" && !validSpotBugsIdentity(finding.LocationRole, 128)) {
		return false
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
	if finding.LocationRole != "" {
		evidence["locationRole"] = finding.LocationRole
	}
	return evidence
}
