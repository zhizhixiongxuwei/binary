package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"binaryscan.local/backend/internal/sourceindex"
	"github.com/gin-gonic/gin"
)

type sourceFunction struct {
	Name      string `json:"name"`
	Signature string `json:"signature"`
	StartLine int    `json:"startLine"`
	EndLine   int    `json:"endLine"`
}

// Older published projects are indexed once, under a project-row lock. Every
// file is hash checked before its declarations are committed.
func (s *taskService) ensureProjectSymbols(ctx context.Context, target explanationTarget) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var project sourceProjectPath
	var indexed sql.NullTime
	err = tx.QueryRowContext(ctx, `SELECT p.id, p.source_kind, p.root_storage_key, p.symbols_indexed_at
        FROM source_projects p JOIN tasks t ON t.id = p.task_id AND t.deleted_at IS NULL
        WHERE p.id = ? AND p.task_id = ? AND p.state = 'ready' FOR UPDATE`, target.ProjectID, target.TaskID).Scan(&project.id, &project.sourceKind, &project.storageKey, &indexed)
	if errors.Is(err, sql.ErrNoRows) {
		return llmFailure("source_project_not_found", "源码项目不存在或已删除。", http.StatusNotFound)
	}
	if err != nil {
		return fmt.Errorf("load project index state: %w", err)
	}
	if indexed.Valid {
		return tx.Commit()
	}
	root, err := s.sourceProjectRoot(project)
	if err != nil {
		return sourceIntegrityError()
	}
	rows, err := tx.QueryContext(ctx, `SELECT id, source_project_id, logical_path, language, HEX(sha256), size_bytes, line_count
        FROM source_files WHERE source_project_id = ? AND state = 'ready' ORDER BY logical_path, id`, project.id)
	if err != nil {
		return err
	}
	files := make([]sourceFileRecord, 0)
	for rows.Next() {
		var file sourceFileRecord
		if err := rows.Scan(&file.ID, &file.ProjectID, &file.LogicalPath, &file.Language, &file.SHA256, &file.SizeBytes, &file.LineCount); err != nil {
			rows.Close()
			return err
		}
		files = append(files, file)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM source_symbols WHERE source_project_id = ?`, project.id); err != nil {
		return err
	}
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return err
		}
		body, err := readExplanationSource(root, file)
		if err != nil {
			return err
		}
		if err := sourceindex.Store(ctx, tx, project.id, file.ID, sourceindex.Functions(file.Language, string(body))); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE source_projects SET symbols_indexed_at = CURRENT_TIMESTAMP(6) WHERE id = ?`, project.id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *taskService) listSourceFunctions(c *gin.Context) {
	target := explanationTarget{TaskID: c.Param("taskID"), ProjectID: c.Param("projectID"), FileID: c.Param("fileID")}
	if err := s.ensureProjectSymbols(c.Request.Context(), target); err != nil {
		writeLLMError(c, err)
		return
	}
	rows, err := s.db.QueryContext(c, `SELECT ss.name, ss.signature, ss.start_line, ss.end_line
        FROM source_symbols ss JOIN source_files sf ON sf.id = ss.source_file_id AND sf.state = 'ready'
        WHERE ss.source_project_id = ? AND ss.source_file_id = ? AND ss.symbol_kind = 'function'
        ORDER BY ss.start_line, ss.id LIMIT 1000`, target.ProjectID, target.FileID)
	if err != nil {
		writeLLMError(c, err)
		return
	}
	defer rows.Close()
	functions := make([]sourceFunction, 0)
	for rows.Next() {
		var function sourceFunction
		if err := rows.Scan(&function.Name, &function.Signature, &function.StartLine, &function.EndLine); err != nil {
			writeLLMError(c, err)
			return
		}
		function.Signature = strings.TrimSpace(function.Signature)
		functions = append(functions, function)
	}
	if err := rows.Err(); err != nil {
		writeLLMError(c, err)
		return
	}
	var exists int
	err = s.db.QueryRowContext(c, `SELECT 1 FROM source_files WHERE id = ? AND source_project_id = ? AND state = 'ready'`, target.FileID, target.ProjectID).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		writeLLMError(c, llmFailure("source_file_not_found", "源码文件不存在或已删除。", 404))
		return
	}
	if err != nil {
		writeLLMError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"functions": functions})
}
