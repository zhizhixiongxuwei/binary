package scanner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"binaryscan.local/backend/internal/identity"
	"binaryscan.local/backend/internal/job"
	"binaryscan.local/backend/internal/storage"
)

const (
	checkerBatchFiles    = 200
	checkerBatchBytes    = 32 << 20
	checkerResponseBytes = 64 << 20
	checkerFindingLimit  = 10000
)

type checkerProject struct {
	id             string
	taskID         string
	decompileRunID string
	sourceKind     string
	language       string
	quality        string
	storageKey     string
	manifestSHA256 []byte
}

type checkerSource struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

type checkerRequest struct {
	Version   string          `json:"version"`
	ProjectID string          `json:"projectId"`
	Language  string          `json:"language"`
	Files     []checkerSource `json:"files"`
}

type checkerFinding struct {
	RuleID   string         `json:"ruleId"`
	Severity string         `json:"severity"`
	CWE      string         `json:"cwe"`
	Path     string         `json:"path"`
	Line     int            `json:"line"`
	Column   int            `json:"column"`
	Title    string         `json:"title"`
	Message  string         `json:"message"`
	Evidence map[string]any `json:"evidence"`
}

type checkerResponse struct {
	Version     string           `json:"version"`
	ProjectID   string           `json:"projectId"`
	Status      string           `json:"status"`
	Findings    []checkerFinding `json:"findings"`
	Diagnostics []string         `json:"diagnostics"`
}

type checkerSourceEvidence struct {
	file  storage.ManifestFile
	lines []string
}

type validatedCheckerFinding struct {
	finding          checkerFinding
	source           checkerSourceEvidence
	startLine        int
	startColumn      int
	endLine          int
	endColumn        int
	snippet          string
	snippetStartLine int
}

func (e *Executor) check(ctx context.Context, claim job.Claim) error {
	project, err := e.loadCheckerProject(ctx, claim.RunID)
	if err != nil {
		return err
	}
	if project.quality == "bytecode_only" {
		return fmt.Errorf("checker requires source code")
	}
	url, err := e.checkerURL(project.language)
	if err != nil {
		return err
	}
	projectRoot, manifest, err := e.openProject(project)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 20 * time.Minute}
	allFindings := make([]checkerFinding, 0)
	responses := make([]checkerResponse, 0)
	diagnostics := make([]string, 0)
	sources := make(map[string]checkerSourceEvidence, len(manifest.Files))
	partial := false
	batch := make([]checkerSource, 0, checkerBatchFiles)
	batchBytes := 0
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		response, err := callChecker(ctx, client, url, checkerRequest{
			Version: "checker-v1", ProjectID: project.id, Language: project.language, Files: batch,
		})
		if err != nil {
			return err
		}
		if response.Status == "partial" {
			partial = true
		}
		responses = append(responses, response)
		diagnostics = append(diagnostics, response.Diagnostics...)
		batch = make([]checkerSource, 0, checkerBatchFiles)
		batchBytes = 0
		remaining := checkerFindingLimit - len(allFindings)
		if remaining <= 0 {
			partial = true
			return nil
		}
		if len(response.Findings) > remaining {
			response.Findings = response.Findings[:remaining]
			partial = true
		}
		allFindings = append(allFindings, response.Findings...)
		return nil
	}

	for _, source := range manifest.Files {
		if source.Language != project.language {
			continue
		}
		cleaned, err := storage.CleanRelativePath(source.Path)
		if err != nil {
			return fmt.Errorf("invalid project manifest path: %w", err)
		}
		filename := filepath.Join(projectRoot, filepath.FromSlash(cleaned))
		info, err := os.Lstat(filename)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("project source is not a regular file: %s", cleaned)
		}
		if info.Size() > 4<<20 {
			partial = true
			diagnostics = append(diagnostics, cleaned+": source exceeds checker file limit")
			continue
		}
		file, err := os.Open(filename)
		if err != nil {
			return err
		}
		body, readErr := io.ReadAll(io.LimitReader(file, (4<<20)+1))
		closeErr := file.Close()
		if readErr != nil || closeErr != nil || len(body) > 4<<20 {
			return fmt.Errorf("read project source %s: read=%v close=%v", cleaned, readErr, closeErr)
		}
		if int64(len(body)) != source.SizeBytes || !strings.EqualFold(
			fmt.Sprintf("%x", sha256.Sum256(body)), source.SHA256,
		) {
			return fmt.Errorf("project source does not match manifest: %s", cleaned)
		}
		lines := strings.Split(string(body), "\n")
		if source.ID == "" || source.LineCount != len(lines) {
			return fmt.Errorf("project source metadata does not match manifest: %s", cleaned)
		}
		sources[cleaned] = checkerSourceEvidence{file: source, lines: lines}
		if len(batch) >= checkerBatchFiles || batchBytes+len(body) > checkerBatchBytes {
			if err := flush(); err != nil {
				return err
			}
		}
		batch = append(batch, checkerSource{Path: cleaned, Content: string(body)})
		batchBytes += len(body)
	}
	if err := flush(); err != nil {
		return err
	}

	validated := make([]validatedCheckerFinding, 0, len(allFindings))
	for _, finding := range allFindings {
		cleaned, cleanErr := storage.CleanRelativePath(finding.Path)
		source, exists := sources[cleaned]
		if cleanErr != nil || !exists {
			partial = true
			diagnostics = append(diagnostics, truncate(finding.Path, 1024)+": checker returned an unknown source path")
			continue
		}
		line := finding.Line
		column := finding.Column
		if column <= 0 {
			column = 1
		}
		if line <= 0 || line > len(source.lines) {
			partial = true
			diagnostics = append(diagnostics, cleaned+": checker returned an out-of-range source location")
			continue
		}
		endColumn, locationOK := utf16FindingEndColumn(source.lines[line-1], column)
		if !locationOK {
			partial = true
			diagnostics = append(diagnostics, cleaned+": checker returned an out-of-range source location")
			continue
		}
		snippet, snippetStart := sourceSnippet(source.lines, line, 2)
		finding.Path = cleaned
		validated = append(validated, validatedCheckerFinding{
			finding: finding, source: source, startLine: line, startColumn: column,
			endLine: line, endColumn: endColumn, snippet: snippet, snippetStartLine: snippetStart,
		})
	}

	artifactBody, err := json.MarshalIndent(map[string]any{
		"schema": "checker-evidence-v1", "projectId": project.id, "language": project.language,
		"responses": responses, "diagnostics": diagnostics, "validatedFindingCount": len(validated),
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("encode checker evidence: %w", err)
	}
	artifactFile, err := os.CreateTemp(e.cfg.Worker.WorkRoot, "checker-evidence-*.json")
	if err != nil {
		return fmt.Errorf("create checker evidence: %w", err)
	}
	artifactPath := artifactFile.Name()
	defer os.Remove(artifactPath)
	if _, err := artifactFile.Write(artifactBody); err != nil {
		artifactFile.Close()
		return fmt.Errorf("write checker evidence: %w", err)
	}
	if err := artifactFile.Sync(); err != nil {
		artifactFile.Close()
		return fmt.Errorf("sync checker evidence: %w", err)
	}
	if err := artifactFile.Close(); err != nil {
		return fmt.Errorf("close checker evidence: %w", err)
	}
	artifactKey, artifactSize, err := publishArtifact(
		e.cfg.Worker.ArtifactRoot, project.taskID, claim.RunID, claim.FencingToken,
		"checker-response.json", artifactPath,
	)
	if err != nil {
		return err
	}
	artifactID, err := identity.UUID()
	if err != nil {
		return err
	}
	artifactSHA := sha256.Sum256(artifactBody)
	artifactMetadata, _ := json.Marshal(map[string]any{
		"projectId": project.id, "language": project.language, "batchCount": len(responses),
		"diagnosticCount": len(diagnostics), "findingCount": len(validated),
	})

	return e.jobs.WithFence(ctx, claim, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "DELETE FROM findings WHERE run_id = ?", claim.RunID); err != nil {
			return fmt.Errorf("replace checker findings: %w", err)
		}
		statement, err := tx.PrepareContext(ctx, `INSERT INTO findings
			(task_id, run_id, source_project_id, source_file_id, finding_type, language,
			 severity, rule_id, cwe, logical_path, start_line, start_column, end_line,
			 end_column, title, message, snippet, snippet_start_line, details)
			VALUES (?, ?, ?, ?, 'code', ?, ?, ?, NULLIF(?, ''), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return err
		}
		defer statement.Close()
		for _, finding := range validated {
			evidence, _ := json.Marshal(finding.finding.Evidence)
			if _, err := statement.ExecContext(ctx, project.taskID, claim.RunID, project.id, finding.source.file.ID,
				project.language, normalizeSeverity(finding.finding.Severity), truncate(finding.finding.RuleID, 128),
				truncate(finding.finding.CWE, 32), truncate(finding.finding.Path, 1024),
				finding.startLine, finding.startColumn, finding.endLine, finding.endColumn,
				truncate(finding.finding.Title, 512), truncate(finding.finding.Message, 8192),
				finding.snippet, finding.snippetStartLine, evidence); err != nil {
				return fmt.Errorf("insert checker finding: %w", err)
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO run_artifacts
			(id, task_id, run_id, artifact_kind, media_type, storage_key, size_bytes,
			 sha256, schema_version, state, metadata)
			VALUES (?, ?, ?, 'checker-response-json', 'application/json', ?, ?, ?,
			 'checker-evidence-v1', 'ready', ?)
			ON DUPLICATE KEY UPDATE storage_key = VALUES(storage_key), size_bytes = VALUES(size_bytes),
			 sha256 = VALUES(sha256), schema_version = VALUES(schema_version), state = 'ready',
			 metadata = VALUES(metadata), deleted_at = NULL`, artifactID, project.taskID, claim.RunID,
			artifactKey, artifactSize, artifactSHA[:], artifactMetadata); err != nil {
			return fmt.Errorf("record checker artifact: %w", err)
		}
		quality := "source"
		if partial {
			quality = "partial_source"
		}
		if _, err := tx.ExecContext(ctx, `UPDATE runs
            SET result_quality = ?, tool_name = ?, ruleset_version = 'checker-v1' WHERE id = ?`,
			quality, project.language+"-checker", claim.RunID); err != nil {
			return fmt.Errorf("record checker runtime: %w", err)
		}
		message := fmt.Sprintf("%s 源码检查完成，发现 %d 条问题", strings.ToUpper(project.language), len(validated))
		if _, err := tx.ExecContext(ctx, `INSERT INTO task_events
            (task_id, event_type, message) VALUES (?, 'check.complete', ?)`, project.taskID, message); err != nil {
			return fmt.Errorf("record checker completion: %w", err)
		}
		return nil
	})
}

func (e *Executor) loadCheckerProject(ctx context.Context, runID string) (checkerProject, error) {
	var project checkerProject
	err := e.db.QueryRowContext(ctx, `SELECT p.id, p.task_id, p.run_id, p.source_kind,
		p.language, p.result_quality, p.root_storage_key, p.manifest_sha256
		FROM runs r JOIN source_projects p ON p.id = r.subject_id AND p.task_id = r.task_id
		WHERE r.id = ? AND r.subject_type = 'source_project' AND p.state = 'ready'`, runID).Scan(
		&project.id, &project.taskID, &project.decompileRunID, &project.sourceKind,
		&project.language, &project.quality, &project.storageKey, &project.manifestSHA256)
	if err != nil {
		return checkerProject{}, fmt.Errorf("load checker source project: %w", err)
	}
	return project, nil
}

func (e *Executor) checkerURL(language string) (string, error) {
	var value string
	switch language {
	case "c":
		value = e.cfg.Worker.CCheckerURL
	case "java":
		value = e.cfg.Worker.JavaCheckerURL
	case "python":
		value = e.cfg.Worker.PythonCheckerURL
	}
	value = strings.TrimRight(strings.TrimSpace(value), "/")
	if value == "" {
		return "", fmt.Errorf("%s checker URL is not configured", language)
	}
	return value + "/v1/check", nil
}

func (e *Executor) openProject(project checkerProject) (string, storage.Manifest, error) {
	if project.sourceKind != "native" && project.sourceKind != "jvm" && project.sourceKind != "pyc" {
		return "", storage.Manifest{}, fmt.Errorf("invalid source project kind")
	}
	key, err := storage.CleanRelativePath(project.storageKey)
	if err != nil {
		return "", storage.Manifest{}, err
	}
	root := filepath.Join(e.cfg.Worker.ProjectRoot, project.sourceKind, filepath.FromSlash(key))
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", storage.Manifest{}, fmt.Errorf("source project root is unavailable")
	}
	body, err := os.ReadFile(filepath.Join(root, "project.json"))
	if err != nil {
		return "", storage.Manifest{}, fmt.Errorf("read source project manifest: %w", err)
	}
	var manifest storage.Manifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		return "", storage.Manifest{}, fmt.Errorf("parse source project manifest: %w", err)
	}
	digest := sha256.Sum256(body)
	if len(project.manifestSHA256) != len(digest) || !bytes.Equal(project.manifestSHA256, digest[:]) {
		return "", storage.Manifest{}, fmt.Errorf("source project manifest digest does not match database record")
	}
	if manifest.Version != "project-v2" || manifest.ProjectID != project.id ||
		manifest.RunID != project.decompileRunID || manifest.Language != project.language ||
		len(manifest.Files) > 5000 {
		return "", storage.Manifest{}, fmt.Errorf("source project manifest does not match database record")
	}
	return root, manifest, nil
}

func sourceSnippet(lines []string, line, radius int) (string, int) {
	start := line - radius
	if start < 1 {
		start = 1
	}
	end := line + radius
	if end > len(lines) {
		end = len(lines)
	}
	return strings.Join(lines[start-1:end], "\n"), start
}

// utf16FindingEndColumn validates a checker-v1 Monaco column and returns an
// exclusive end column spanning the Unicode scalar at that position. Monaco
// columns are one-based UTF-16 code-unit offsets, so supplementary characters
// occupy two columns while BMP characters occupy one.
func utf16FindingEndColumn(line string, startColumn int) (int, bool) {
	maxColumn := utf16CodeUnitCount(line) + 1
	if startColumn < 1 || startColumn > maxColumn {
		return 0, false
	}
	if startColumn == maxColumn {
		return maxColumn, true
	}
	targetOffset := startColumn - 1
	consumed := 0
	for _, character := range line {
		width := 1
		if character > 0xffff {
			width = 2
		}
		next := consumed + width
		if targetOffset == consumed {
			return next + 1, true
		}
		if targetOffset < next {
			// Reject a position between a supplementary character's two
			// surrogate halves; it is not a stable source-character boundary.
			return 0, false
		}
		consumed = next
	}
	return maxColumn, true
}

func utf16CodeUnitCount(value string) int {
	count := 0
	for _, character := range value {
		count++
		if character > 0xffff {
			count++
		}
	}
	return count
}

func callChecker(ctx context.Context, client *http.Client, url string, request checkerRequest) (checkerResponse, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return checkerResponse{}, err
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return checkerResponse{}, err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	response, err := client.Do(httpRequest)
	if err != nil {
		return checkerResponse{}, job.Retryable(fmt.Errorf("call checker: %w", err), 15*time.Second)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, checkerResponseBytes+1))
	if err != nil {
		return checkerResponse{}, job.Retryable(fmt.Errorf("read checker response: %w", err), 15*time.Second)
	}
	if len(responseBody) > checkerResponseBytes {
		return checkerResponse{}, fmt.Errorf("checker response exceeds the supported size")
	}
	if response.StatusCode != http.StatusOK {
		if response.StatusCode == http.StatusRequestTimeout || response.StatusCode == http.StatusTooManyRequests ||
			response.StatusCode >= http.StatusInternalServerError {
			return checkerResponse{}, job.Retryable(
				fmt.Errorf("checker returned HTTP %d: %s", response.StatusCode, truncate(string(responseBody), 1024)),
				15*time.Second,
			)
		}
		return checkerResponse{}, fmt.Errorf("checker returned HTTP %d: %s", response.StatusCode, truncate(string(responseBody), 1024))
	}
	var result checkerResponse
	if err := json.Unmarshal(responseBody, &result); err != nil {
		return checkerResponse{}, fmt.Errorf("parse checker response: %w", err)
	}
	if result.Version != "checker-v1" || result.ProjectID != request.ProjectID ||
		(result.Status != "complete" && result.Status != "partial") || len(result.Findings) > checkerFindingLimit {
		return checkerResponse{}, fmt.Errorf("checker response violates checker-v1")
	}
	return result, nil
}
