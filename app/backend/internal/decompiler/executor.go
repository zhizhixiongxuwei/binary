package decompiler

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"binaryscan.local/backend/internal/config"
	"binaryscan.local/backend/internal/identity"
	"binaryscan.local/backend/internal/job"
	"binaryscan.local/backend/internal/storage"
	"binaryscan.local/backend/internal/worker"
)

const (
	maxProjectBytes = 256 << 20
	maxSourceBytes  = 4 << 20
	maxSourceFiles  = 5000
	maxToolLogBytes = 1 << 20
)

type Mode string

const (
	ModeNative Mode = "native"
	ModeJVM    Mode = "jvm"
	ModePYC    Mode = "pyc"
)

type Executor struct {
	mode Mode
	cfg  config.Config
	db   *sql.DB
	jobs *job.Repository
}

type subject struct {
	taskID         string
	fileID         string
	blobID         string
	blobSHA256     string
	logicalPath    string
	detectedFormat string
	storageKey     string
}

type toolResult struct {
	outputRoot string
	toolName   string
	quality    string
	extension  string
}

func Native(cfg config.Config, db *sql.DB, jobs *job.Repository) (worker.Executor, error) {
	return newExecutor(ModeNative, cfg, db, jobs)
}

func JVM(cfg config.Config, db *sql.DB, jobs *job.Repository) (worker.Executor, error) {
	return newExecutor(ModeJVM, cfg, db, jobs)
}

func PYC(cfg config.Config, db *sql.DB, jobs *job.Repository) (worker.Executor, error) {
	return newExecutor(ModePYC, cfg, db, jobs)
}

func newExecutor(mode Mode, cfg config.Config, db *sql.DB, jobs *job.Repository) (worker.Executor, error) {
	for _, root := range []string{cfg.Worker.WorkRoot, cfg.Worker.BlobRoot, cfg.Worker.ProjectRoot} {
		if !filepath.IsAbs(root) {
			return nil, fmt.Errorf("decompiler path must be absolute: %s", root)
		}
	}
	if err := os.MkdirAll(cfg.Worker.WorkRoot, 0o700); err != nil {
		return nil, fmt.Errorf("create decompiler work root: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(cfg.Worker.ProjectRoot, ".staging"), 0o700); err != nil {
		return nil, fmt.Errorf("create project staging root: %w", err)
	}
	return &Executor{mode: mode, cfg: cfg, db: db, jobs: jobs}, nil
}

func (e *Executor) Execute(ctx context.Context, claim job.Claim) error {
	subject, err := e.loadSubject(ctx, claim.RunID)
	if err != nil {
		return err
	}
	if !e.supports(subject.detectedFormat) {
		return fmt.Errorf("%s decompiler does not support format %q", e.mode, subject.detectedFormat)
	}
	inputPath, err := e.blobPath(subject.storageKey)
	if err != nil {
		return err
	}
	workRoot, err := os.MkdirTemp(e.cfg.Worker.WorkRoot, string(e.mode)+"-"+claim.RunID+"-")
	if err != nil {
		return fmt.Errorf("create decompiler workspace: %w", err)
	}
	defer os.RemoveAll(workRoot)
	result, err := e.runTool(ctx, workRoot, inputPath, subject)
	if err != nil {
		return err
	}

	workspace, err := storage.NewWorkspace(filepath.Join(e.cfg.Worker.ProjectRoot, ".staging"), claim.RunID, maxProjectBytes)
	if err != nil {
		return err
	}
	defer workspace.Cleanup()
	partial, err := collectSources(workspace, result.outputRoot, result.extension, e.language())
	if err != nil {
		return err
	}
	if partial {
		result.quality = "partial_source"
	}
	fileCount, sizeBytes := workspace.Stats()
	if fileCount == 0 {
		return fmt.Errorf("%s produced no supported source files", result.toolName)
	}
	projectID, err := identity.UUID()
	if err != nil {
		return err
	}
	publication, err := workspace.PublishProject(e.cfg.Worker.ProjectRoot, projectID, storage.Manifest{
		RunID: claim.RunID, InputBlobID: subject.blobID, InputSHA256: subject.blobSHA256,
		InputPath: subject.logicalPath, Kind: string(e.mode), Language: e.language(), Quality: result.quality,
		ToolName: result.toolName, ToolVersion: e.cfg.Worker.ToolVersion,
	})
	if err != nil {
		return err
	}
	return e.jobs.WithFence(ctx, claim, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO source_projects
			(id, task_id, file_node_id, input_blob_id, run_id, source_kind, language, result_quality,
			 root_storage_key, manifest_sha256, file_count, size_bytes, state)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ready')
			ON DUPLICATE KEY UPDATE id = VALUES(id), result_quality = VALUES(result_quality),
			  root_storage_key = VALUES(root_storage_key), manifest_sha256 = VALUES(manifest_sha256),
			  input_blob_id = VALUES(input_blob_id), file_count = VALUES(file_count),
			  size_bytes = VALUES(size_bytes), state = 'ready', deleted_at = NULL`,
			projectID, subject.taskID, subject.fileID, subject.blobID, claim.RunID, e.mode, e.language(), result.quality,
			projectID, publication.ManifestSHA256[:], fileCount, sizeBytes); err != nil {
			return fmt.Errorf("publish source project record: %w", err)
		}
		for _, source := range publication.Manifest.Files {
			digest, err := hex.DecodeString(source.SHA256)
			if err != nil || len(digest) != 32 {
				return fmt.Errorf("invalid source digest for %s", source.Path)
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO source_files
				(id, source_project_id, logical_path, language, sha256, size_bytes, line_count, state)
				VALUES (?, ?, ?, ?, ?, ?, ?, 'ready')
				ON DUPLICATE KEY UPDATE id = VALUES(id), language = VALUES(language),
				  sha256 = VALUES(sha256), size_bytes = VALUES(size_bytes),
				  line_count = VALUES(line_count), state = 'ready', deleted_at = NULL`,
				source.ID, projectID, source.Path, source.Language, digest, source.SizeBytes, source.LineCount); err != nil {
				return fmt.Errorf("publish source file %s: %w", source.Path, err)
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE runs
            SET result_quality = ?, tool_name = ?, tool_version = ? WHERE id = ?`,
			result.quality, result.toolName, e.cfg.Worker.ToolVersion, claim.RunID); err != nil {
			return fmt.Errorf("record decompiler runtime: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO task_events
            (task_id, event_type, message) VALUES (?, 'decompile.complete', ?)`, subject.taskID,
			fmt.Sprintf("%s 反编译完成，共 %d 个源码文件", e.mode, fileCount)); err != nil {
			return fmt.Errorf("record decompile completion: %w", err)
		}
		return nil
	})
}

func (e *Executor) runTool(ctx context.Context, workRoot, inputPath string, subject subject) (toolResult, error) {
	switch e.mode {
	case ModeNative:
		return e.runGhidra(ctx, workRoot, inputPath)
	case ModeJVM:
		return e.runJVM(ctx, workRoot, inputPath, subject.detectedFormat)
	case ModePYC:
		return e.runPYC(ctx, workRoot, inputPath)
	default:
		return toolResult{}, fmt.Errorf("unsupported decompiler mode %q", e.mode)
	}
}

func (e *Executor) runGhidra(ctx context.Context, workRoot, inputPath string) (toolResult, error) {
	projectRoot := filepath.Join(workRoot, "ghidra-project")
	outputRoot := filepath.Join(workRoot, "source")
	if err := os.MkdirAll(projectRoot, 0o700); err != nil {
		return toolResult{}, err
	}
	args := []string{projectRoot, "binaryscan", "-import", inputPath,
		"-scriptPath", e.cfg.Worker.GhidraScriptRoot, "-postScript", "ExportPseudoC.java",
		outputRoot, strconvI(maxSourceFiles), strconvI64(maxProjectBytes), "-deleteProject"}
	if err := runCommand(ctx, 90*time.Minute, workRoot, e.cfg.Worker.GhidraPath, args...); err != nil {
		return toolResult{}, err
	}
	quality := "source"
	if _, err := os.Stat(filepath.Join(outputRoot, ".binaryscan-partial")); err == nil {
		quality = "partial_source"
	}
	return toolResult{outputRoot: outputRoot, toolName: "ghidra", quality: quality, extension: ".c"}, nil
}

func (e *Executor) runJVM(ctx context.Context, workRoot, inputPath, format string) (toolResult, error) {
	stagedInput := filepath.Join(workRoot, "input."+jvmInputExtension(format))
	if err := os.Symlink(inputPath, stagedInput); err != nil {
		return toolResult{}, fmt.Errorf("stage JVM input: %w", err)
	}
	inputPath = stagedInput
	if format == "apk" || format == "dex" {
		outputRoot := filepath.Join(workRoot, "jadx")
		if err := os.MkdirAll(outputRoot, 0o700); err != nil {
			return toolResult{}, err
		}
		err := runCommand(ctx, 45*time.Minute, workRoot, e.cfg.Worker.JavaPath,
			"-Xms128m", "-Xmx3g", "-XX:+ExitOnOutOfMemoryError", "-cp", e.cfg.Worker.JADXJar,
			"jadx.cli.JadxCLI", "--output-dir", outputRoot, "--no-res", "--threads-count", "2", inputPath)
		if err != nil {
			return toolResult{}, err
		}
		return toolResult{outputRoot: outputRoot, toolName: "jadx", quality: "source", extension: ".java"}, nil
	}
	vineflowerOutput := filepath.Join(workRoot, "vineflower")
	if err := os.MkdirAll(vineflowerOutput, 0o700); err != nil {
		return toolResult{}, err
	}
	err := runCommand(ctx, 45*time.Minute, workRoot, e.cfg.Worker.JavaPath,
		"-Xms128m", "-Xmx3g", "-XX:+ExitOnOutOfMemoryError", "-jar", e.cfg.Worker.VineflowerJar,
		"--silent", "--folder", inputPath, vineflowerOutput)
	if err == nil {
		return toolResult{outputRoot: vineflowerOutput, toolName: "vineflower", quality: "source", extension: ".java"}, nil
	}
	cfrOutput := filepath.Join(workRoot, "cfr")
	if mkdirErr := os.MkdirAll(cfrOutput, 0o700); mkdirErr != nil {
		return toolResult{}, mkdirErr
	}
	if cfrErr := runCommand(ctx, 45*time.Minute, workRoot, e.cfg.Worker.JavaPath,
		"-Xms128m", "-Xmx3g", "-XX:+ExitOnOutOfMemoryError", "-jar", e.cfg.Worker.CFRJar,
		inputPath, "--outputdir", cfrOutput, "--silent", "true"); cfrErr != nil {
		return toolResult{}, fmt.Errorf("vineflower failed (%v); CFR failed (%v)", err, cfrErr)
	}
	return toolResult{outputRoot: cfrOutput, toolName: "cfr", quality: "partial_source", extension: ".java"}, nil
}

func jvmInputExtension(format string) string {
	switch format {
	case "class", "java-class":
		return "class"
	case "jar", "war", "ear", "dex", "apk":
		return format
	default:
		return "bin"
	}
}

func (e *Executor) runPYC(ctx context.Context, workRoot, inputPath string) (toolResult, error) {
	outputRoot := filepath.Join(workRoot, "source")
	if err := os.MkdirAll(outputRoot, 0o700); err != nil {
		return toolResult{}, err
	}
	outputPath := filepath.Join(outputRoot, "decompiled.py")
	output, err := os.OpenFile(outputPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return toolResult{}, err
	}
	executionCtx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	command := exec.CommandContext(executionCtx, e.cfg.Worker.PYCDCPath, inputPath)
	command.Env = append(os.Environ(), "HOME="+workRoot, "TMPDIR="+workRoot)
	var stderr limitedBuffer
	stderr.limit = maxToolLogBytes
	command.Stdout = output
	command.Stderr = &stderr
	runErr := command.Run()
	closeErr := output.Close()
	if closeErr != nil {
		return toolResult{}, closeErr
	}
	info, statErr := os.Stat(outputPath)
	if statErr != nil {
		return toolResult{}, statErr
	}
	quality := "source"
	if runErr != nil {
		if info.Size() == 0 {
			return toolResult{}, fmt.Errorf("pycdc failed: %w: %s", runErr, stderr.String())
		}
		quality = "partial_source"
	}
	return toolResult{outputRoot: outputRoot, toolName: "pycdc", quality: quality, extension: ".py"}, nil
}

func (e *Executor) loadSubject(ctx context.Context, runID string) (subject, error) {
	var value subject
	err := e.db.QueryRowContext(ctx, `SELECT r.task_id, f.id, b.id, HEX(b.sha256), f.logical_path, f.detected_format, b.storage_key
		FROM runs r JOIN file_nodes f ON f.id = r.subject_id AND f.task_id = r.task_id
        JOIN blobs b ON b.id = f.blob_id AND b.state = 'ready'
        WHERE r.id = ? AND r.subject_type = 'file_node' LIMIT 1`, runID).Scan(
		&value.taskID, &value.fileID, &value.blobID, &value.blobSHA256,
		&value.logicalPath, &value.detectedFormat, &value.storageKey)
	if err != nil {
		return subject{}, fmt.Errorf("load decompile subject: %w", err)
	}
	return value, nil
}

func (e *Executor) blobPath(storageKey string) (string, error) {
	cleaned, err := storage.CleanRelativePath(storageKey)
	if err != nil {
		return "", err
	}
	value := filepath.Join(e.cfg.Worker.BlobRoot, filepath.FromSlash(cleaned))
	info, err := os.Lstat(value)
	if err != nil || !info.Mode().IsRegular() {
		return "", fmt.Errorf("decompiler input is not a regular blob")
	}
	return value, nil
}

func (e *Executor) supports(format string) bool {
	switch e.mode {
	case ModeNative:
		return format == "pe" || format == "pe32" || format == "pe32+" ||
			format == "elf" || format == "elf32" || format == "elf64" ||
			format == "mach-o" || format == "macho-thin" || format == "macho-fat"
	case ModeJVM:
		return format == "class" || format == "java-class" || format == "jar" ||
			format == "war" || format == "ear" || format == "dex" || format == "apk"
	case ModePYC:
		return format == "pyc"
	default:
		return false
	}
}

func (e *Executor) language() string {
	switch e.mode {
	case ModeNative:
		return "c"
	case ModeJVM:
		return "java"
	case ModePYC:
		return "python"
	default:
		return ""
	}
}

func collectSources(workspace *storage.Workspace, root, extension, language string) (bool, error) {
	partial := false
	count := 0
	err := filepath.WalkDir(root, func(filename string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("decompiler output contains a symbolic link")
		}
		if entry.IsDir() || strings.ToLower(filepath.Ext(entry.Name())) != extension {
			return nil
		}
		if count >= maxSourceFiles {
			partial = true
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("decompiler output is not a regular file")
		}
		if info.Size() > maxSourceBytes {
			partial = true
			return nil
		}
		relative, err := filepath.Rel(root, filename)
		if err != nil {
			return err
		}
		source, err := os.Open(filename)
		if err != nil {
			return err
		}
		writeErr := workspace.WriteFile(filepath.ToSlash(relative), language, source)
		closeErr := source.Close()
		if writeErr != nil {
			return writeErr
		}
		if closeErr != nil {
			return closeErr
		}
		count++
		return nil
	})
	return partial, err
}

func runCommand(ctx context.Context, timeout time.Duration, workRoot, executable string, args ...string) error {
	executionCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	command := exec.CommandContext(executionCtx, executable, args...)
	command.Env = append(os.Environ(), "HOME="+workRoot, "TMPDIR="+workRoot)
	command.Stdout = io.Discard
	var stderr limitedBuffer
	stderr.limit = maxToolLogBytes
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		if errors.Is(executionCtx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("%s timed out", filepath.Base(executable))
		}
		return fmt.Errorf("%s failed: %w: %s", filepath.Base(executable), err, stderr.String())
	}
	return nil
}

type limitedBuffer struct {
	buffer bytes.Buffer
	limit  int
}

func (b *limitedBuffer) Write(value []byte) (int, error) {
	original := len(value)
	remaining := b.limit - b.buffer.Len()
	if remaining > 0 {
		if len(value) > remaining {
			value = value[:remaining]
		}
		_, _ = b.buffer.Write(value)
	}
	return original, nil
}

func (b *limitedBuffer) String() string {
	return strings.TrimSpace(b.buffer.String())
}

func strconvI(value int) string {
	return fmt.Sprintf("%d", value)
}

func strconvI64(value int64) string {
	return fmt.Sprintf("%d", value)
}
