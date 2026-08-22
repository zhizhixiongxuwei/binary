package scanner

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"binaryscan.local/backend/internal/config"
	"binaryscan.local/backend/internal/identity"
	"binaryscan.local/backend/internal/job"
	"binaryscan.local/backend/internal/storage"
	"binaryscan.local/backend/internal/worker"
)

const (
	maxTrivyReportBytes = 128 << 20
	maxTrivyFindings    = 10000
)

type Executor struct {
	cfg   config.Config
	db    *sql.DB
	jobs  *job.Repository
	blobs *storage.BlobStore
}

type subject struct {
	taskID      string
	fileID      string
	logicalPath string
	storageKey  string
}

type trivyReport struct {
	Results []struct {
		Target          string `json:"Target"`
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			PkgName          string `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
			Severity         string `json:"Severity"`
			Title            string `json:"Title"`
			Description      string `json:"Description"`
			PrimaryURL       string `json:"PrimaryURL"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

func New(cfg config.Config, db *sql.DB, jobs *job.Repository) (worker.Executor, error) {
	for _, root := range []string{cfg.Worker.WorkRoot, cfg.Worker.BlobRoot, cfg.Worker.ArtifactRoot} {
		if !filepath.IsAbs(root) {
			return nil, fmt.Errorf("scanner path must be absolute: %s", root)
		}
	}
	if err := os.MkdirAll(cfg.Worker.WorkRoot, 0o700); err != nil {
		return nil, fmt.Errorf("create scanner work root: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(cfg.Worker.ArtifactRoot, ".staging"), 0o700); err != nil {
		return nil, fmt.Errorf("create artifact staging root: %w", err)
	}
	blobs, err := storage.NewBlobStore(cfg.Worker.BlobRoot)
	if err != nil {
		return nil, fmt.Errorf("initialize scanner blob store: %w", err)
	}
	return &Executor{cfg: cfg, db: db, jobs: jobs, blobs: blobs}, nil
}

func (e *Executor) Execute(ctx context.Context, claim job.Claim) error {
	switch claim.Kind {
	case job.KindScan:
		return e.scan(ctx, claim)
	case job.KindTrivyScan:
		return e.trivy(ctx, claim)
	case job.KindArchiveImport:
		return e.archive(ctx, claim)
	case job.KindCCheck, job.KindJavaCheck, job.KindPythonCheck:
		return e.check(ctx, claim)
	default:
		return fmt.Errorf("scanner does not support job kind %q", claim.Kind)
	}
}

func (e *Executor) scan(ctx context.Context, claim job.Claim) error {
	subject, err := e.loadTaskSubject(ctx, claim.RunID)
	if err != nil {
		return err
	}
	inputPath, err := e.blobPath(subject.storageKey)
	if err != nil {
		return err
	}
	format, err := detectFile(inputPath, subject.logicalPath)
	if err != nil {
		return err
	}
	trivyRunID, err := identity.UUID()
	if err != nil {
		return err
	}
	return e.jobs.WithFence(ctx, claim, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE tasks
            SET status = 'scanning', detected_format = ? WHERE id = ? AND deleted_at IS NULL`, format, subject.taskID); err != nil {
			return fmt.Errorf("update detected task format: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE file_nodes
            SET detected_format = ? WHERE id = ? AND task_id = ?`, format, subject.fileID, subject.taskID); err != nil {
			return fmt.Errorf("update detected file format: %w", err)
		}
		idempotencyKey := "auto:" + claim.RunID
		if _, err := tx.ExecContext(ctx, `INSERT INTO runs
            (id, kind, status, task_id, subject_type, subject_id, created_by, idempotency_key, request)
            SELECT ?, 'trivy_scan', 'queued', id, 'task', id, created_by, ?, JSON_OBJECT('source', 'scan')
            FROM tasks WHERE id = ?
            ON DUPLICATE KEY UPDATE id = runs.id`, trivyRunID, idempotencyKey, subject.taskID); err != nil {
			return fmt.Errorf("create automatic trivy run: %w", err)
		}
		if err := tx.QueryRowContext(ctx, `SELECT id FROM runs
            WHERE kind = 'trivy_scan' AND subject_id = ? AND idempotency_key = ?`,
			subject.taskID, idempotencyKey).Scan(&trivyRunID); err != nil {
			return fmt.Errorf("resolve automatic trivy run: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO jobs (run_id, kind, status, max_attempts)
            VALUES (?, 'trivy_scan', 'queued', 2) ON DUPLICATE KEY UPDATE run_id = run_id`, trivyRunID); err != nil {
			return fmt.Errorf("enqueue automatic trivy scan: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE runs
            SET tool_name = 'binaryscan-format-detector', tool_version = ? WHERE id = ?`, e.cfg.Version, claim.RunID); err != nil {
			return fmt.Errorf("record format detector: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO task_events
            (task_id, event_type, message) VALUES (?, 'scan.detected', ?)`,
			subject.taskID, "识别格式："+format); err != nil {
			return fmt.Errorf("record format detection: %w", err)
		}
		return nil
	})
}

func (e *Executor) trivy(ctx context.Context, claim job.Claim) error {
	subject, err := e.loadTaskSubject(ctx, claim.RunID)
	if err != nil {
		return err
	}
	inputPath, err := e.blobPath(subject.storageKey)
	if err != nil {
		return err
	}
	workDirectory, err := os.MkdirTemp(e.cfg.Worker.WorkRoot, "trivy-"+claim.RunID+"-")
	if err != nil {
		return fmt.Errorf("create trivy workspace: %w", err)
	}
	defer os.RemoveAll(workDirectory)
	reportPath := filepath.Join(workDirectory, "trivy.json")
	executionCtx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	command := exec.CommandContext(executionCtx, e.cfg.Worker.TrivyPath,
		"filesystem", "--scanners", "vuln", "--format", "json", "--output", reportPath,
		"--cache-dir", e.cfg.Worker.TrivyCacheRoot, "--skip-db-update", "--skip-java-db-update",
		"--offline-scan", inputPath)
	var stderr bytes.Buffer
	command.Stdout = io.Discard
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		if errors.Is(executionCtx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("trivy timed out")
		}
		return fmt.Errorf("trivy execution failed: %w: %s", err, truncate(stderr.String(), 1024))
	}
	info, err := os.Stat(reportPath)
	if err != nil {
		return fmt.Errorf("inspect trivy report: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > maxTrivyReportBytes {
		return fmt.Errorf("trivy report exceeds the supported size")
	}
	body, err := os.ReadFile(reportPath)
	if err != nil {
		return fmt.Errorf("read trivy report: %w", err)
	}
	var report trivyReport
	if err := json.Unmarshal(body, &report); err != nil {
		return fmt.Errorf("parse trivy report: %w", err)
	}
	artifactKey, artifactSize, err := publishArtifact(
		e.cfg.Worker.ArtifactRoot, subject.taskID, claim.RunID, claim.FencingToken, "trivy.json", reportPath,
	)
	if err != nil {
		return err
	}
	artifactID, err := identity.UUID()
	if err != nil {
		return err
	}
	return e.jobs.WithFence(ctx, claim, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "DELETE FROM findings WHERE run_id = ?", claim.RunID); err != nil {
			return fmt.Errorf("replace trivy findings: %w", err)
		}
		statement, err := tx.PrepareContext(ctx, `INSERT INTO findings
            (task_id, run_id, finding_type, severity, rule_id, external_id, logical_path, title, message, details)
            VALUES (?, ?, 'vulnerability', ?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return fmt.Errorf("prepare trivy finding insert: %w", err)
		}
		defer statement.Close()
		count := 0
		for _, result := range report.Results {
			for _, finding := range result.Vulnerabilities {
				if count >= maxTrivyFindings {
					break
				}
				details, _ := json.Marshal(map[string]string{
					"package": finding.PkgName, "installedVersion": finding.InstalledVersion,
					"fixedVersion": finding.FixedVersion, "primaryUrl": finding.PrimaryURL,
				})
				title := strings.TrimSpace(finding.Title)
				if title == "" {
					title = finding.VulnerabilityID
				}
				message := strings.TrimSpace(finding.Description)
				if message == "" {
					message = title
				}
				if _, err := statement.ExecContext(ctx, subject.taskID, claim.RunID,
					normalizeSeverity(finding.Severity), finding.VulnerabilityID, finding.VulnerabilityID,
					truncate(result.Target, 1024), truncate(title, 512), truncate(message, 8192), details); err != nil {
					return fmt.Errorf("insert trivy finding: %w", err)
				}
				count++
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO run_artifacts
            (id, task_id, run_id, artifact_kind, media_type, storage_key, size_bytes)
            VALUES (?, ?, ?, 'trivy-json', 'application/json', ?, ?)
            ON DUPLICATE KEY UPDATE storage_key = VALUES(storage_key), size_bytes = VALUES(size_bytes)`,
			artifactID, subject.taskID, claim.RunID, artifactKey, artifactSize); err != nil {
			return fmt.Errorf("record trivy artifact: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE runs
            SET tool_name = 'trivy', ruleset_version = 'offline-bundle' WHERE id = ?`, claim.RunID); err != nil {
			return fmt.Errorf("record trivy runtime: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO task_events
            (task_id, event_type, message) VALUES (?, 'trivy.complete', ?)`,
			subject.taskID, fmt.Sprintf("Trivy 完成，发现 %d 条漏洞", count)); err != nil {
			return fmt.Errorf("record trivy completion: %w", err)
		}
		return nil
	})
}

func (e *Executor) loadTaskSubject(ctx context.Context, runID string) (subject, error) {
	var value subject
	err := e.db.QueryRowContext(ctx, `SELECT r.task_id, f.id, f.logical_path, b.storage_key
        FROM runs r
        JOIN tasks t ON t.id = r.task_id
        JOIN file_nodes f ON f.task_id = t.id AND f.blob_id = t.blob_id AND f.parent_id IS NULL
        JOIN blobs b ON b.id = f.blob_id AND b.state = 'ready'
        WHERE r.id = ? AND r.subject_type = 'task' AND t.deleted_at IS NULL
        LIMIT 1`, runID).Scan(&value.taskID, &value.fileID, &value.logicalPath, &value.storageKey)
	if err != nil {
		return subject{}, fmt.Errorf("load task input for run %s: %w", runID, err)
	}
	return value, nil
}

func (e *Executor) blobPath(storageKey string) (string, error) {
	cleaned, err := storage.CleanRelativePath(storageKey)
	if err != nil {
		return "", fmt.Errorf("invalid blob storage key: %w", err)
	}
	value := filepath.Join(e.cfg.Worker.BlobRoot, filepath.FromSlash(cleaned))
	info, err := os.Lstat(value)
	if err != nil {
		return "", fmt.Errorf("open task blob: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("task blob is not a regular file")
	}
	return value, nil
}

func detectFile(filename, logicalPath string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", fmt.Errorf("open file for detection: %w", err)
	}
	defer file.Close()
	header := make([]byte, 512)
	count, err := file.Read(header)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("read file header: %w", err)
	}
	header = header[:count]
	extension := strings.ToLower(filepath.Ext(logicalPath))
	if len(header) >= 2 && bytes.Equal(header[:2], []byte{'M', 'Z'}) {
		return "pe", nil
	}
	if len(header) >= 4 && bytes.Equal(header[:4], []byte{0x7f, 'E', 'L', 'F'}) {
		return "elf", nil
	}
	if len(header) >= 4 && bytes.Equal(header[:4], []byte("dex\n")) {
		return "dex", nil
	}
	if len(header) >= 8 && bytes.Equal(header[:4], []byte{0xca, 0xfe, 0xba, 0xbe}) {
		major := binary.BigEndian.Uint16(header[6:8])
		if major >= 45 && major <= 100 {
			return "class", nil
		}
	}
	if hasMachOMagic(header) {
		return "mach-o", nil
	}
	if len(header) >= 4 && (bytes.Equal(header[:4], []byte{'P', 'K', 3, 4}) || bytes.Equal(header[:4], []byte{'P', 'K', 5, 6})) {
		switch extension {
		case ".apk":
			return "apk", nil
		case ".jar":
			return "jar", nil
		case ".war":
			return "war", nil
		case ".ear":
			return "ear", nil
		default:
			return "zip", nil
		}
	}
	if extension == ".pyc" && len(header) >= 4 {
		return "pyc", nil
	}
	if len(header) >= 6 && bytes.Equal(header[:6], []byte{0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c}) {
		return "7z", nil
	}
	if len(header) >= 2 && bytes.Equal(header[:2], []byte{0x1f, 0x8b}) {
		return "gzip", nil
	}
	if len(header) >= 262 && string(header[257:262]) == "ustar" {
		return "tar", nil
	}
	return "unknown", nil
}

func hasMachOMagic(header []byte) bool {
	if len(header) < 4 {
		return false
	}
	magic := header[:4]
	values := [][]byte{
		{0xfe, 0xed, 0xfa, 0xce}, {0xce, 0xfa, 0xed, 0xfe},
		{0xfe, 0xed, 0xfa, 0xcf}, {0xcf, 0xfa, 0xed, 0xfe},
		{0xca, 0xfe, 0xba, 0xbe}, {0xbe, 0xba, 0xfe, 0xca},
	}
	for _, value := range values {
		if bytes.Equal(magic, value) {
			return true
		}
	}
	return false
}

func publishArtifact(root, taskID, runID string, fence uint64, name, source string) (string, int64, error) {
	for _, value := range []string{taskID, runID, name} {
		if _, err := storage.CleanRelativePath(value); err != nil {
			return "", 0, err
		}
	}
	relative := filepath.Join(taskID, runID, strconv.FormatUint(fence, 10), name)
	destination := filepath.Join(root, relative)
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return "", 0, fmt.Errorf("create artifact directory: %w", err)
	}
	input, err := os.Open(source)
	if err != nil {
		return "", 0, fmt.Errorf("open artifact source: %w", err)
	}
	defer input.Close()
	temporary, err := os.CreateTemp(filepath.Join(root, ".staging"), "artifact-*")
	if err != nil {
		return "", 0, fmt.Errorf("create artifact staging file: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	written, copyErr := io.Copy(temporary, input)
	syncErr := temporary.Sync()
	closeErr := temporary.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil {
		return "", 0, fmt.Errorf("stage artifact: copy=%v sync=%v close=%v", copyErr, syncErr, closeErr)
	}
	if err := os.Link(temporaryName, destination); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return "", 0, fmt.Errorf("publish artifact: %w", err)
		}
		info, statErr := os.Stat(destination)
		if statErr != nil || !info.Mode().IsRegular() || info.Size() != written {
			return "", 0, fmt.Errorf("existing artifact is invalid")
		}
	}
	if err := os.Chmod(destination, 0o440); err != nil {
		return "", 0, fmt.Errorf("make artifact read-only: %w", err)
	}
	return filepath.ToSlash(relative), written, nil
}

func normalizeSeverity(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return "info"
	}
}

func truncate(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}
