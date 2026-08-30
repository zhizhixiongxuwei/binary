package scanner

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
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
	"binaryscan.local/backend/internal/containerarchive"
	"binaryscan.local/backend/internal/filetype"
	"binaryscan.local/backend/internal/identity"
	"binaryscan.local/backend/internal/job"
	"binaryscan.local/backend/internal/storage"
	"binaryscan.local/backend/internal/worker"
)

const (
	maxTrivyReportBytes = 128 << 20
	maxTrivyFindings    = 10000
)

// Executor 是格式识别、归档导入、容器漏洞扫描和源码 checker 的统一调度入口；
// 具体执行路径共享 BlobStore、任务 Repository 和同一套 fenced 发布语义。
type Executor struct {
	cfg   config.Config
	db    *sql.DB
	jobs  *job.Repository
	blobs *storage.BlobStore
}

type subject struct {
	taskID         string
	fileID         string
	logicalPath    string
	storageKey     string
	inputCategory  string
	detectedFormat string
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

// New 校验所有持久化根目录为绝对路径，并预建仅 worker 可写的暂存区。
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

// Execute 只按已领取 job 的 Kind 分派，未知类型立即失败，避免错误角色静默消费不属于自己的任务。
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

// scan 对持久化 Blob 再做一次内容识别，并核对上传阶段记录的类别，防止元数据漂移或错误引用。
// 识别为归档时，在同一个 fenced 事务中以 scan run 派生的幂等键创建一次自动导入运行和作业。
func (e *Executor) scan(ctx context.Context, claim job.Claim) error {
	subject, err := e.loadTaskSubject(ctx, claim.RunID)
	if err != nil {
		return err
	}
	inputPath, err := e.blobPath(subject.storageKey)
	if err != nil {
		return err
	}
	detected, err := filetype.Detect(inputPath, subject.logicalPath)
	if err != nil {
		return err
	}
	if detected.Category == "" || detected.Format == "unknown" {
		return fmt.Errorf("unsupported input format")
	}
	if subject.inputCategory != "" && string(detected.Category) != subject.inputCategory {
		return fmt.Errorf("input category changed after upload validation: expected %s, detected %s", subject.inputCategory, detected.Category)
	}
	var archiveRunID string
	if detected.Category == filetype.CategoryArchive {
		archiveRunID, err = identity.UUID()
		if err != nil {
			return err
		}
	}
	return e.jobs.WithFence(ctx, claim, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE tasks
			SET status = 'ready', detected_category = ?, detected_format = ?
			WHERE id = ? AND deleted_at IS NULL`, detected.Category, detected.Format, subject.taskID); err != nil {
			return fmt.Errorf("update detected task format: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE file_nodes
			SET detected_format = ? WHERE id = ? AND task_id = ?`, detected.Format, subject.fileID, subject.taskID); err != nil {
			return fmt.Errorf("update detected file format: %w", err)
		}
		if detected.Category == filetype.CategoryArchive {
			idempotencyKey := "auto-archive:" + claim.RunID
			if _, err := tx.ExecContext(ctx, `INSERT INTO runs
				(id, kind, status, task_id, subject_type, subject_id, created_by, idempotency_key, request)
				SELECT ?, 'archive_import', 'queued', id, 'file_node', ?, created_by, ?, JSON_OBJECT('source', 'scan')
				FROM tasks WHERE id = ?
				ON DUPLICATE KEY UPDATE id = runs.id`, archiveRunID, subject.fileID, idempotencyKey, subject.taskID); err != nil {
				return fmt.Errorf("create automatic archive import: %w", err)
			}
			if err := tx.QueryRowContext(ctx, `SELECT id FROM runs
				WHERE kind = 'archive_import' AND subject_id = ? AND idempotency_key = ?`,
				subject.fileID, idempotencyKey).Scan(&archiveRunID); err != nil {
				return fmt.Errorf("resolve automatic archive import: %w", err)
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO jobs (run_id, kind, status, max_attempts)
				VALUES (?, 'archive_import', 'queued', 3) ON DUPLICATE KEY UPDATE run_id = run_id`, archiveRunID); err != nil {
				return fmt.Errorf("enqueue automatic archive import: %w", err)
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE runs
            SET tool_name = 'binaryscan-format-detector', tool_version = ? WHERE id = ?`, e.cfg.Version, claim.RunID); err != nil {
			return fmt.Errorf("record format detector: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO task_events
			(task_id, event_type, message) VALUES (?, 'scan.detected', ?)`,
			subject.taskID, "识别格式："+detected.Format); err != nil {
			return fmt.Errorf("record format detection: %w", err)
		}
		return nil
	})
}

// trivy 在单次运行目录中准备离线数据库和输入，限制总执行时间、报告大小及最多入库的发现数。
// 原始 JSON 制品以 fence 代次写入不可变路径；发现、制品元数据和完成事件再通过 WithFence 一次发布，
// 旧 worker 即使晚到也只能留下不可引用的代次文件，不能覆盖当前运行结果。
func (e *Executor) trivy(ctx context.Context, claim job.Claim) error {
	subject, err := e.loadTrivySubject(ctx, claim.RunID)
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
	executionCtx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	cacheDirectory, err := prepareTrivyCache(e.cfg.Worker.TrivyCacheRoot, workDirectory)
	if err != nil {
		return fmt.Errorf("prepare trivy cache: %w", err)
	}
	trivyInput, err := prepareTrivyInput(executionCtx, inputPath, subject.detectedFormat, workDirectory,
		e.cfg.Worker.ArchiveMaxBytes, e.cfg.Worker.ArchiveMaxFiles)
	if err != nil {
		if errors.Is(executionCtx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("trivy timed out")
		}
		return fmt.Errorf("prepare trivy input: %w", err)
	}
	reportPath := filepath.Join(workDirectory, "trivy.json")
	command := exec.CommandContext(executionCtx, e.cfg.Worker.TrivyPath,
		trivyImageArgs(cacheDirectory, reportPath, trivyInput)...)
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
					"package_name": finding.PkgName, "installed_version": finding.InstalledVersion,
					"fixed_version": finding.FixedVersion, "primary_url": finding.PrimaryURL,
					"target": result.Target, "image_logical_path": subject.logicalPath,
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
		artifactDigest := sha256.Sum256(body)
		if _, err := tx.ExecContext(ctx, `INSERT INTO run_artifacts
			(id, task_id, run_id, artifact_kind, media_type, storage_key, size_bytes, sha256, schema_version, state)
			VALUES (?, ?, ?, 'trivy-json', 'application/json', ?, ?, ?, 'trivy-json-v1', 'ready')
			ON DUPLICATE KEY UPDATE storage_key = VALUES(storage_key), size_bytes = VALUES(size_bytes),
				sha256 = VALUES(sha256), schema_version = VALUES(schema_version), state = 'ready', deleted_at = NULL`,
			artifactID, subject.taskID, claim.RunID, artifactKey, artifactSize, artifactDigest[:]); err != nil {
			return fmt.Errorf("record trivy artifact: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE runs
			SET tool_name = 'trivy', ruleset_version = 'offline-bundle', image_reference = ? WHERE id = ?`,
			subject.logicalPath, claim.RunID); err != nil {
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
	err := e.db.QueryRowContext(ctx, `SELECT r.task_id, f.id, f.logical_path, b.storage_key, COALESCE(t.input_category, '')
        FROM runs r
        JOIN tasks t ON t.id = r.task_id
        JOIN file_nodes f ON f.task_id = t.id AND f.blob_id = t.blob_id AND f.parent_id IS NULL
        JOIN blobs b ON b.id = f.blob_id AND b.state = 'ready'
        WHERE r.id = ? AND r.subject_type = 'task' AND t.deleted_at IS NULL
		LIMIT 1`, runID).Scan(&value.taskID, &value.fileID, &value.logicalPath, &value.storageKey, &value.inputCategory)
	if err != nil {
		return subject{}, fmt.Errorf("load task input for run %s: %w", runID, err)
	}
	return value, nil
}

func (e *Executor) loadTrivySubject(ctx context.Context, runID string) (subject, error) {
	var value subject
	err := e.db.QueryRowContext(ctx, `SELECT r.task_id, f.id, f.logical_path, b.storage_key, f.detected_format
		FROM runs r
		JOIN tasks t ON t.id = r.task_id AND t.deleted_at IS NULL
		JOIN file_nodes f ON f.id = r.subject_id AND f.task_id = t.id
		JOIN blobs b ON b.id = f.blob_id AND b.state = 'ready'
		WHERE r.id = ? AND r.kind = 'trivy_scan' AND r.subject_type = 'file_node'
		  AND f.detected_format IN ('docker-tar', 'oci-tar')`, runID).Scan(
		&value.taskID, &value.fileID, &value.logicalPath, &value.storageKey, &value.detectedFormat,
	)
	if err != nil {
		return subject{}, fmt.Errorf("load container image input for run %s: %w", runID, err)
	}
	return value, nil
}

func trivyImageArgs(cacheRoot, reportPath, inputPath string) []string {
	return []string{"image", "--input", inputPath, "--scanners", "vuln", "--format", "json", "--output", reportPath,
		"--cache-dir", cacheRoot, "--skip-db-update", "--skip-java-db-update", "--offline-scan"}
}

// prepareTrivyCache 保持镜像内置的大型漏洞数据库只读，同时给 Trivy 提供每次运行独立的可写缓存根。
// 即使禁用全部数据库更新，Trivy 仍会在 --cache-dir 下创建 fanal 缓存，因此不能直接指向只读的
// /opt/trivy-cache；这里只把已校验的 db/java-db 目录链接到运行目录，数据库本体不会被修改。
func prepareTrivyCache(databaseRoot, workDirectory string) (string, error) {
	if !filepath.IsAbs(databaseRoot) || !filepath.IsAbs(workDirectory) {
		return "", fmt.Errorf("trivy cache paths must be absolute")
	}
	cacheDirectory := filepath.Join(workDirectory, "cache")
	if err := os.Mkdir(cacheDirectory, 0o700); err != nil {
		return "", fmt.Errorf("create writable cache root: %w", err)
	}
	for _, database := range []struct {
		directory string
		files     []string
	}{
		{directory: "db", files: []string{"metadata.json", "trivy.db"}},
		{directory: "java-db", files: []string{"metadata.json", "trivy-java.db"}},
	} {
		sourceDirectory := filepath.Join(databaseRoot, database.directory)
		info, err := os.Lstat(sourceDirectory)
		if err != nil || !info.IsDir() {
			return "", fmt.Errorf("database directory %s is unavailable", database.directory)
		}
		for _, name := range database.files {
			fileInfo, statErr := os.Lstat(filepath.Join(sourceDirectory, name))
			if statErr != nil || !fileInfo.Mode().IsRegular() || fileInfo.Size() <= 0 {
				return "", fmt.Errorf("database file %s/%s is unavailable", database.directory, name)
			}
		}
		if err := os.Symlink(sourceDirectory, filepath.Join(cacheDirectory, database.directory)); err != nil {
			return "", fmt.Errorf("link database directory %s: %w", database.directory, err)
		}
	}
	return cacheDirectory, nil
}

// prepareTrivyInput 对 Docker save TAR 直接传递文件；Trivy 只接受目录形式的 OCI layout，
// 因而后者必须先在受限运行目录中安全展开。
func prepareTrivyInput(
	ctx context.Context,
	inputPath, detectedFormat, workDirectory string,
	maxBytes int64,
	maxFiles int,
) (string, error) {
	switch detectedFormat {
	case containerarchive.FormatDockerTAR:
		return inputPath, nil
	case containerarchive.FormatOCITAR:
		layoutRoot := filepath.Join(workDirectory, "oci-layout")
		if err := extractOCIImageLayout(ctx, inputPath, layoutRoot, maxBytes, maxFiles); err != nil {
			return "", err
		}
		return layoutRoot, nil
	default:
		return "", fmt.Errorf("unsupported container input format %q", detectedFormat)
	}
}

// extractOCIImageLayout 将上传的 OCI layout TAR 物化到单次运行目录，因为 Trivy 的 OCI 输入要求目录。
// 成员名必须是安全相对路径，只允许目录和以 O_EXCL 创建的普通只读文件；链接与特殊文件全部拒绝，
// 同时限制条目数和累计展开字节，最后验证 oci-layout、index.json 与 blobs 的基本拓扑。
func extractOCIImageLayout(
	ctx context.Context,
	inputPath, layoutRoot string,
	maxBytes int64,
	maxFiles int,
) error {
	if maxBytes <= 0 || maxFiles <= 0 {
		return fmt.Errorf("OCI extraction limits must be positive")
	}
	input, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("open OCI layout archive: %w", err)
	}
	defer input.Close()
	if err := os.Mkdir(layoutRoot, 0o700); err != nil {
		return fmt.Errorf("create OCI layout root: %w", err)
	}

	reader := tar.NewReader(input)
	var expandedBytes int64
	entries := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		header, nextErr := reader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return fmt.Errorf("read OCI layout archive: %w", nextErr)
		}
		entries++
		if entries > maxFiles {
			return fmt.Errorf("OCI layout entry limit exceeded")
		}
		cleaned, cleanErr := storage.CleanRelativePath(header.Name)
		if cleanErr != nil {
			return fmt.Errorf("invalid OCI layout member %q: %w", header.Name, cleanErr)
		}
		destination := filepath.Join(layoutRoot, filepath.FromSlash(cleaned))
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(destination, 0o700); err != nil {
				return fmt.Errorf("create OCI layout directory: %w", err)
			}
		case tar.TypeReg, tar.TypeRegA:
			if header.Size < 0 || header.Size > maxBytes-expandedBytes {
				return fmt.Errorf("OCI layout expanded byte limit exceeded")
			}
			if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
				return fmt.Errorf("create OCI layout parent: %w", err)
			}
			output, openErr := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o400)
			if openErr != nil {
				return fmt.Errorf("create OCI layout member %s: %w", cleaned, openErr)
			}
			written, copyErr := copyNWithContext(ctx, output, reader, header.Size)
			closeErr := output.Close()
			if copyErr != nil || closeErr != nil || written != header.Size {
				return fmt.Errorf("write OCI layout member %s: copy=%v close=%v", cleaned,
					copyErr, closeErr)
			}
			expandedBytes += written
		default:
			return fmt.Errorf("OCI layout member %s has unsupported type %d", cleaned, header.Typeflag)
		}
	}

	for _, name := range []string{"oci-layout", "index.json"} {
		info, err := os.Lstat(filepath.Join(layoutRoot, name))
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("OCI layout is missing %s", name)
		}
	}
	blobs, err := os.Lstat(filepath.Join(layoutRoot, "blobs"))
	if err != nil || !blobs.IsDir() {
		return fmt.Errorf("OCI layout is missing blobs directory")
	}
	return nil
}

func copyNWithContext(ctx context.Context, destination io.Writer, source io.Reader, size int64) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	written, err := io.CopyN(destination, &contextReader{ctx: ctx, reader: source}, size)
	if err == nil {
		err = ctx.Err()
	}
	return written, err
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
	detected, err := filetype.Detect(filename, logicalPath)
	if err != nil {
		return "", err
	}
	return detected.Format, nil
}

// publishArtifact 以 task/run/fence/name 隔离每次租约代次，经 fsync 的暂存文件通过硬链接原子发布。
// 已存在目标只有在仍为同大小普通文件时才可复用，最终权限设为只读；数据库是否引用它由后续 fence 决定。
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
