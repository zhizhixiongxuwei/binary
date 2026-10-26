package app

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"binaryscan.local/backend/internal/llm"
	"binaryscan.local/backend/internal/storage"
)

type explanationTarget struct{ TaskID, ProjectID, FileID string }
type explanationSource struct {
	sourceFileRecord
	Content string
}

// Explanations use the same ready-state, task and content hash boundaries as the
// source viewer. No source text or storage path is accepted from the caller.
func (s *taskService) loadExplanationSource(ctx context.Context, target explanationTarget) (explanationSource, error) {
	var project sourceProjectPath
	var source explanationSource
	err := s.db.QueryRowContext(ctx, `SELECT p.id, p.source_kind, p.root_storage_key,
		sf.id, sf.source_project_id, sf.logical_path, sf.language, sf.media_type,
		HEX(sf.sha256), sf.size_bytes, sf.line_count
		FROM source_projects p
		JOIN source_files sf ON sf.source_project_id = p.id AND sf.state = 'ready'
		JOIN tasks t ON t.id = p.task_id AND t.deleted_at IS NULL
		WHERE p.id = ? AND p.task_id = ? AND sf.id = ? AND p.state = 'ready'`,
		target.ProjectID, target.TaskID, target.FileID).Scan(&project.id, &project.sourceKind, &project.storageKey,
		&source.ID, &source.ProjectID, &source.LogicalPath, &source.Language, &source.MediaType,
		&source.SHA256, &source.SizeBytes, &source.LineCount)
	if errors.Is(err, sql.ErrNoRows) {
		return source, llmFailure("source_file_not_found", "源码文件不存在或已删除。", http.StatusNotFound)
	}
	if err != nil {
		return source, llmFailure("source_file_query_failed", "暂时无法读取源码信息。", http.StatusInternalServerError)
	}
	if source.SizeBytes < 0 || source.SizeBytes > maxSourceFileContentBytes {
		return source, llmFailure("llm_input_too_large", "源码文件超过读取上限，请选择较小的文件。", http.StatusRequestEntityTooLarge)
	}
	root, err := s.sourceProjectRoot(project)
	if err != nil {
		return source, sourceIntegrityError()
	}
	body, err := readExplanationSource(root, source.sourceFileRecord)
	if err != nil {
		return source, err
	}
	source.Content = string(body)
	source.SHA256 = strings.ToLower(source.SHA256)
	return source, nil
}

func sourceIntegrityError() error {
	return llmFailure("source_storage_corrupt", "源码存储校验失败，请重新生成源码。", http.StatusConflict)
}

func readExplanationSource(root string, file sourceFileRecord) ([]byte, error) {
	cleaned, err := storage.CleanRelativePath(file.LogicalPath)
	if err != nil || file.SizeBytes < 0 || file.SizeBytes > maxSourceFileContentBytes {
		return nil, sourceIntegrityError()
	}
	// Reject symlinks at every level, and use an OS root handle to prevent a path
	// swap from escaping the project between verification and reading.
	cursor := root
	for _, part := range strings.Split(cleaned, "/") {
		cursor = filepath.Join(cursor, part)
		info, statErr := os.Lstat(cursor)
		if statErr != nil || info.Mode()&os.ModeSymlink != 0 {
			return nil, sourceIntegrityError()
		}
	}
	fsroot, err := os.OpenRoot(root)
	if err != nil {
		return nil, sourceIntegrityError()
	}
	defer fsroot.Close()
	fileHandle, err := fsroot.Open(filepath.FromSlash(cleaned))
	if err != nil {
		return nil, sourceIntegrityError()
	}
	defer fileHandle.Close()
	info, err := fileHandle.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != file.SizeBytes {
		return nil, sourceIntegrityError()
	}
	body, err := io.ReadAll(io.LimitReader(fileHandle, maxSourceFileContentBytes+1))
	if err != nil || int64(len(body)) != file.SizeBytes || !utf8.Valid(body) {
		return nil, sourceIntegrityError()
	}
	digest := sha256.Sum256(body)
	if !strings.EqualFold(hex.EncodeToString(digest[:]), file.SHA256) {
		return nil, sourceIntegrityError()
	}
	return body, nil
}

func explanationInput(source explanationSource, request explanationRequest, limit int) (prompt string, start, end int, err error) {
	lines := strings.Split(strings.ReplaceAll(source.Content, "\r\n", "\n"), "\n")
	start, end = 1, len(lines)
	if request.Scope == "selection" {
		if request.StartLine == nil || request.EndLine == nil || *request.StartLine < 1 || *request.EndLine < *request.StartLine || *request.EndLine > len(lines) {
			return "", 0, 0, llmFailure("llm_invalid_range", "请选择文件中的有效行范围。", http.StatusBadRequest)
		}
		start, end = *request.StartLine, *request.EndLine
	} else if request.Scope != "file" || request.StartLine != nil || request.EndLine != nil {
		return "", 0, 0, llmFailure("llm_invalid_scope", "整文件解释无需行范围，选区解释必须提供起止行。", http.StatusBadRequest)
	}
	selected := strings.Join(lines[start-1:end], "\n")
	if utf8.RuneCountInString(selected) > limit {
		return "", 0, 0, llmFailure("llm_input_too_large", fmt.Sprintf("本次源码超过 %d 字符上限，请缩小选区。", limit), http.StatusRequestEntityTooLarge)
	}
	var numbered strings.Builder
	for index := start; index <= end; index++ {
		fmt.Fprintf(&numbered, "L%d: %s\n", index, lines[index-1])
	}
	// The model sees only the requested file/range. The boundary labels describe
	// untrusted data; they never grant instructions embedded in the source priority.
	prompt = fmt.Sprintf("请用中文解释以下%s源码的%s范围（L%d–L%d）。说明目的、主要流程、关键函数和限制；引用 L 行号；缺少上下文的结论标明‘推断’。源码可能来自反编译，变量名和类型未必准确。不要声称运行了代码。\n<untrusted_source>\n%s</untrusted_source>", source.Language, request.Scope, start, end, numbered.String())
	return prompt, start, end, nil
}

func explanationCacheKey(source explanationSource, settings llm.Snapshot, scope string, start, end int) string {
	value := fmt.Sprintf("source-explanation-v1\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%d\x00%d\x00%d",
		source.SHA256, source.Language, settings.Provider, settings.BaseURL, settings.Model, scope, start, end, settings.MaxOutputTokens)
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}
