package sourceindex

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"binaryscan.local/backend/internal/identity"
)

// Store writes the declarations of one immutable file in bounded batches.
func Store(ctx context.Context, tx *sql.Tx, projectID, fileID string, functions []Function) error {
	const batchSize = 100
	for offset := 0; offset < len(functions); offset += batchSize {
		end := min(offset+batchSize, len(functions))
		args := make([]any, 0, (end-offset)*8)
		values := make([]string, 0, end-offset)
		for _, function := range functions[offset:end] {
			id, err := identity.UUID()
			if err != nil {
				return err
			}
			values = append(values, "(?, ?, ?, 'function', ?, ?, ?, 1, ?, 1, ?)")
			args = append(args, id, projectID, fileID, function.Name, function.Signature, function.StartLine, function.EndLine, function.SearchText)
		}
		query := `INSERT INTO source_symbols
			(id, source_project_id, source_file_id, symbol_kind, name, signature, start_line, start_column, end_line, end_column, search_text)
            VALUES ` + strings.Join(values, ",")
		if _, err := tx.ExecContext(ctx, query, args...); err != nil {
			return fmt.Errorf("store source symbols: %w", err)
		}
	}
	return nil
}
