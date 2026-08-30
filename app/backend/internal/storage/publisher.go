package storage

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
	"unicode/utf8"

	"binaryscan.local/backend/internal/identity"
)

// Manifest 是已发布源码项目的自描述索引，绑定输入 Blob、生成工具和每个源码文件的摘要。
type Manifest struct {
	Version     string         `json:"version"`
	ProjectID   string         `json:"projectId"`
	RunID       string         `json:"runId"`
	InputBlobID string         `json:"inputBlobId"`
	InputSHA256 string         `json:"inputSha256"`
	InputPath   string         `json:"inputPath"`
	Kind        string         `json:"kind"`
	Language    string         `json:"language"`
	Quality     string         `json:"quality"`
	ToolName    string         `json:"toolName"`
	ToolVersion string         `json:"toolVersion"`
	Files       []ManifestFile `json:"files"`
	PublishedAt time.Time      `json:"publishedAt"`
}

type ManifestFile struct {
	ID        string `json:"id"`
	Path      string `json:"path"`
	Language  string `json:"language"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"sizeBytes"`
	LineCount int    `json:"lineCount"`
}

// Publication 返回不可变项目根目录及 manifest 本身的摘要，供数据库记录和后续完整性校验使用。
type Publication struct {
	Root           string
	Manifest       Manifest
	ManifestSHA256 [32]byte
}

// Workspace 是单次反编译运行的私有暂存区；所有输出先完成路径、大小和编码校验，再整体发布。
type Workspace struct {
	root     string
	runID    string
	files    map[string]ManifestFile
	maxBytes int64
	written  int64
}

func (w *Workspace) Stats() (int, int64) {
	return len(w.files), w.written
}

// NewWorkspace 以已清洗的 runID 创建权限为 0700 的独立目录，并为整个项目设置累计字节上限。
func NewWorkspace(workRoot, runID string, maxBytes int64) (*Workspace, error) {
	runID, err := cleanIdentifier(runID)
	if err != nil {
		return nil, err
	}
	if maxBytes <= 0 {
		return nil, fmt.Errorf("workspace byte limit must be positive")
	}
	absRoot, err := filepath.Abs(workRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve work root: %w", err)
	}
	if err := os.MkdirAll(absRoot, 0o700); err != nil {
		return nil, fmt.Errorf("create staging root: %w", err)
	}
	root, err := os.MkdirTemp(absRoot, runID+"-")
	if err != nil {
		return nil, fmt.Errorf("create workspace: %w", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		os.RemoveAll(root)
		return nil, fmt.Errorf("secure workspace: %w", err)
	}
	return &Workspace{root: root, runID: runID, files: make(map[string]ManifestFile), maxBytes: maxBytes}, nil
}

// WriteFile 只接受规范化相对路径和 UTF-8 文本，拒绝重复路径及保留的 project.json。
// SHA-256、大小和行数在写入时生成，累计上限阻止工具输出膨胀占满制品盘。
func (w *Workspace) WriteFile(relativePath, language string, source io.Reader) error {
	cleaned, err := CleanRelativePath(relativePath)
	if err != nil {
		return err
	}
	if cleaned == "project.json" {
		return fmt.Errorf("project.json is reserved for the publication manifest")
	}
	if _, exists := w.files[cleaned]; exists {
		return fmt.Errorf("duplicate workspace path %q", cleaned)
	}
	destination := filepath.Join(w.root, filepath.FromSlash(cleaned))
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create output file: %w", err)
	}
	remaining := w.maxBytes - w.written
	hash := sha256.New()
	lines := &lineCounter{}
	written, copyErr := io.Copy(io.MultiWriter(file, hash, lines), io.LimitReader(source, remaining+1))
	closeErr := file.Close()
	if copyErr != nil {
		return fmt.Errorf("write output file: %w", copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close output file: %w", closeErr)
	}
	if written > remaining {
		return fmt.Errorf("workspace exceeds %d bytes", w.maxBytes)
	}
	body, err := os.ReadFile(destination)
	if err != nil {
		return fmt.Errorf("validate output file: %w", err)
	}
	if !utf8.Valid(body) {
		return fmt.Errorf("source output %q is not valid UTF-8", cleaned)
	}
	fileID, err := identity.UUID()
	if err != nil {
		return err
	}
	w.written += written
	w.files[cleaned] = ManifestFile{
		ID: fileID, Path: cleaned, Language: language, SHA256: fmt.Sprintf("%x", hash.Sum(nil)),
		SizeBytes: written, LineCount: lines.Count(written),
	}
	return nil
}

func (w *Workspace) Publish(finalRoot, projectID string, manifest Manifest) (string, error) {
	publication, err := w.PublishProject(finalRoot, projectID, manifest)
	return publication.Root, err
}

// PublishProject 将排序后的文件清单写入 project.json，再以目录 rename 原子切换到最终项目 ID。
// 目标必须不存在，发布后整个目录树转为只读；消费者因此只能看到完整项目，不会读到半成品。
func (w *Workspace) PublishProject(finalRoot, projectID string, manifest Manifest) (Publication, error) {
	projectID, err := cleanIdentifier(projectID)
	if err != nil {
		return Publication{}, err
	}
	if manifest.RunID != w.runID {
		return Publication{}, fmt.Errorf("manifest run ID does not match workspace")
	}
	manifest.Version = "project-v2"
	manifest.ProjectID = projectID
	manifest.PublishedAt = time.Now().UTC()
	manifest.Files = make([]ManifestFile, 0, len(w.files))
	for _, file := range w.files {
		manifest.Files = append(manifest.Files, file)
	}
	sort.Slice(manifest.Files, func(i, j int) bool { return manifest.Files[i].Path < manifest.Files[j].Path })
	body, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return Publication{}, fmt.Errorf("encode project manifest: %w", err)
	}
	if err := os.WriteFile(filepath.Join(w.root, "project.json"), body, 0o600); err != nil {
		return Publication{}, fmt.Errorf("write project manifest: %w", err)
	}
	absFinalRoot, err := filepath.Abs(finalRoot)
	if err != nil {
		return Publication{}, fmt.Errorf("resolve project root: %w", err)
	}
	if err := os.MkdirAll(absFinalRoot, 0o700); err != nil {
		return Publication{}, fmt.Errorf("create project root: %w", err)
	}
	destination := filepath.Join(absFinalRoot, projectID)
	if _, err := os.Lstat(destination); err == nil {
		return Publication{}, fmt.Errorf("project destination already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return Publication{}, fmt.Errorf("inspect project destination: %w", err)
	}
	if err := os.Rename(w.root, destination); err != nil {
		return Publication{}, fmt.Errorf("atomically publish project: %w", err)
	}
	w.root = ""
	if err := makeReadOnly(destination); err != nil {
		return Publication{Root: destination, Manifest: manifest, ManifestSHA256: sha256.Sum256(body)}, err
	}
	return Publication{Root: destination, Manifest: manifest, ManifestSHA256: sha256.Sum256(body)}, nil
}

type lineCounter struct {
	newlines int
}

func (c *lineCounter) Write(value []byte) (int, error) {
	for _, character := range value {
		if character == '\n' {
			c.newlines++
		}
	}
	return len(value), nil
}

func (c *lineCounter) Count(_ int64) int {
	return c.newlines + 1
}

func makeReadOnly(root string) error {
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		mode := os.FileMode(0o440)
		if entry.IsDir() {
			mode = 0o550
		}
		if err := os.Chmod(path, mode); err != nil {
			return fmt.Errorf("make published project read-only: %w", err)
		}
		return nil
	})
}

// Cleanup 只删除尚未发布的暂存目录；PublishProject 成功后 root 会被清空，避免误删不可变项目。
func (w *Workspace) Cleanup() error {
	if w.root == "" {
		return nil
	}
	return os.RemoveAll(w.root)
}
