package scanner

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

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
	diagnostics := make([]string, 0)
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

	return e.jobs.WithFence(ctx, claim, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "DELETE FROM findings WHERE run_id = ?", claim.RunID); err != nil {
			return fmt.Errorf("replace checker findings: %w", err)
		}
		statement, err := tx.PrepareContext(ctx, `INSERT INTO findings
            (task_id, run_id, finding_type, language, severity, rule_id, cwe,
             logical_path, start_line, start_column, title, message, details)
            VALUES (?, ?, 'code', ?, ?, ?, NULLIF(?, ''), ?, NULLIF(?, 0),
                    NULLIF(?, 0), ?, ?, ?)`)
		if err != nil {
			return err
		}
		defer statement.Close()
		for _, finding := range allFindings {
			evidence, _ := json.Marshal(finding.Evidence)
			if _, err := statement.ExecContext(ctx, project.taskID, claim.RunID, project.language,
				normalizeSeverity(finding.Severity), truncate(finding.RuleID, 128), truncate(finding.CWE, 32),
				truncate(finding.Path, 1024), finding.Line, finding.Column, truncate(finding.Title, 512),
				truncate(finding.Message, 8192), evidence); err != nil {
				return fmt.Errorf("insert checker finding: %w", err)
			}
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
		message := fmt.Sprintf("%s 源码检查完成，发现 %d 条问题", strings.ToUpper(project.language), len(allFindings))
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
        p.language, p.result_quality, p.root_storage_key
        FROM runs r JOIN source_projects p ON p.id = r.subject_id AND p.task_id = r.task_id
        WHERE r.id = ? AND r.subject_type = 'source_project' AND p.state = 'ready'`, runID).Scan(
		&project.id, &project.taskID, &project.decompileRunID, &project.sourceKind,
		&project.language, &project.quality, &project.storageKey)
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
	if manifest.Version != "project-v1" || manifest.RunID != project.decompileRunID || manifest.Language != project.language || len(manifest.Files) > 5000 {
		return "", storage.Manifest{}, fmt.Errorf("source project manifest does not match database record")
	}
	return root, manifest, nil
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
		return checkerResponse{}, fmt.Errorf("call checker: %w", err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, checkerResponseBytes+1))
	if err != nil {
		return checkerResponse{}, fmt.Errorf("read checker response: %w", err)
	}
	if len(responseBody) > checkerResponseBytes {
		return checkerResponse{}, fmt.Errorf("checker response exceeds the supported size")
	}
	if response.StatusCode != http.StatusOK {
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
