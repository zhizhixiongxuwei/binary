package database

import (
	"context"
	"database/sql"
	"fmt"

	"binaryscan.local/backend/internal/identity"

	"golang.org/x/crypto/bcrypt"
)

func BootstrapAdministrator(ctx context.Context, db *sql.DB, username, password string) error {
	var count int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE role = 'administrator'").Scan(&count); err != nil {
		return fmt.Errorf("count administrators: %w", err)
	}
	if count != 0 {
		return nil
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash initial administrator password: %w", err)
	}
	publicID, err := identity.UUID()
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `INSERT INTO users
        (public_id, username, password_hash, role, active, must_change_password)
        VALUES (?, ?, ?, 'administrator', TRUE, TRUE)`, publicID, username, string(hash))
	if err != nil {
		return fmt.Errorf("create initial administrator: %w", err)
	}
	return nil
}
