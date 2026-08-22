package database

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"

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
	publicID, err := randomUUID()
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

func randomUUID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate identifier: %w", err)
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(value[:])
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" +
		encoded[16:20] + "-" + encoded[20:32], nil
}
