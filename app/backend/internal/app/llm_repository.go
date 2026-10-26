package app

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

type explanationRecord struct {
	ID           string    `json:"id"`
	TaskID       string    `json:"taskId"`
	ProjectID    string    `json:"projectId"`
	FileID       string    `json:"fileId"`
	SourceSHA256 string    `json:"sourceSha256"`
	Scope        string    `json:"scope"`
	StartLine    int       `json:"startLine"`
	EndLine      int       `json:"endLine"`
	Provider     string    `json:"provider"`
	Model        string    `json:"model"`
	Text         string    `json:"text"`
	Status       string    `json:"status"`
	CreatedAt    time.Time `json:"createdAt"`
	Stale        bool      `json:"stale"`
	CacheHit     bool      `json:"cacheHit,omitempty"`
	ErrorCode    string    `json:"errorCode,omitempty"`
	CacheKey     string    `json:"-"`
	CreatedBy    uint64    `json:"-"`
}

type explanationRepository interface {
	List(context.Context, explanationTarget) ([]explanationRecord, error)
	FindRequest(context.Context, explanationTarget, string) (explanationRecord, error)
	FindCache(context.Context, explanationTarget, string) (explanationRecord, error)
	Insert(context.Context, explanationRecord) error
	Finish(context.Context, explanationRecord) error
}

type sqlExplanationRepository struct{ db *sql.DB }

const recoverInterruptedExplanationsSQL = `UPDATE llm_explanations
	SET status = 'failed', error_code = 'llm_interrupted', updated_at = UTC_TIMESTAMP(6)
	WHERE status = 'generating'`

func (r sqlExplanationRepository) RecoverInterrupted(ctx context.Context) error {
	// Only status metadata changes: partial content and original provenance stay
	// intact, and already completed/cancelled/failed records are not rewritten.
	_, err := r.db.ExecContext(ctx, recoverInterruptedExplanationsSQL)
	return err
}

const explanationColumns = `id, task_id, source_project_id, source_file_id,
	LOWER(HEX(source_sha256)), scope, start_line, end_line, provider, model,
	content, status, created_at, error_code, LOWER(HEX(cache_key))`

type explanationScanner interface{ Scan(...any) error }

func scanExplanation(row explanationScanner) (explanationRecord, error) {
	var item explanationRecord
	err := row.Scan(&item.ID, &item.TaskID, &item.ProjectID, &item.FileID, &item.SourceSHA256,
		&item.Scope, &item.StartLine, &item.EndLine, &item.Provider, &item.Model,
		&item.Text, &item.Status, &item.CreatedAt, &item.ErrorCode, &item.CacheKey)
	return item, err
}

func (r sqlExplanationRepository) List(ctx context.Context, target explanationTarget) ([]explanationRecord, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+explanationColumns+` FROM llm_explanations
		WHERE task_id = ? AND source_project_id = ? AND source_file_id = ?
		ORDER BY created_at DESC, id DESC LIMIT 100`, target.TaskID, target.ProjectID, target.FileID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]explanationRecord, 0)
	for rows.Next() {
		item, err := scanExplanation(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (r sqlExplanationRepository) FindRequest(ctx context.Context, target explanationTarget, id string) (explanationRecord, error) {
	return scanExplanation(r.db.QueryRowContext(ctx, `SELECT `+explanationColumns+` FROM llm_explanations
		WHERE task_id = ? AND source_project_id = ? AND source_file_id = ? AND id = ?`, target.TaskID, target.ProjectID, target.FileID, id))
}

func (r sqlExplanationRepository) FindCache(ctx context.Context, target explanationTarget, key string) (explanationRecord, error) {
	return scanExplanation(r.db.QueryRowContext(ctx, `SELECT `+explanationColumns+` FROM llm_explanations
		WHERE task_id = ? AND source_project_id = ? AND source_file_id = ? AND cache_key = UNHEX(?) AND status = 'completed'
		ORDER BY created_at DESC, id DESC LIMIT 1`, target.TaskID, target.ProjectID, target.FileID, key))
}

func (r sqlExplanationRepository) Insert(ctx context.Context, item explanationRecord) error {
	// INSERT SELECT locks the task while checking visibility. A concurrent soft
	// deletion therefore either removes this row or prevents its creation.
	result, err := r.db.ExecContext(ctx, `INSERT INTO llm_explanations
		(id, task_id, source_project_id, source_file_id, created_by, source_sha256,
		cache_key, scope, start_line, end_line, provider, model, content, status, created_at)
		SELECT ?, t.id, p.id, sf.id, ?, UNHEX(?), UNHEX(?), ?, ?, ?, ?, ?, '', 'generating', ?
		FROM tasks t JOIN source_projects p ON p.task_id = t.id AND p.state = 'ready'
		JOIN source_files sf ON sf.source_project_id = p.id AND sf.state = 'ready'
		WHERE t.id = ? AND p.id = ? AND sf.id = ? AND t.deleted_at IS NULL AND sf.sha256 = UNHEX(?)`,
		item.ID, item.CreatedBy, item.SourceSHA256, item.CacheKey, item.Scope, item.StartLine,
		item.EndLine, item.Provider, item.Model, item.CreatedAt,
		item.TaskID, item.ProjectID, item.FileID, item.SourceSHA256)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return sql.ErrNoRows
	}
	return nil
}

func (r sqlExplanationRepository) Finish(ctx context.Context, item explanationRecord) error {
	result, err := r.db.ExecContext(ctx, `UPDATE llm_explanations
		SET content = ?, status = ?, error_code = ?, updated_at = UTC_TIMESTAMP(6)
		WHERE id = ? AND status = 'generating'`, item.Text, item.Status, item.ErrorCode, item.ID)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return errors.New("explanation no longer exists or has finished")
	}
	return nil
}
