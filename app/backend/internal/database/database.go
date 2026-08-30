package database

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"binaryscan.local/backend/internal/config"

	"github.com/go-sql-driver/mysql"
)

func Open(ctx context.Context, cfg config.Database) (*sql.DB, error) {
	// 所有时间按 UTC 解析，文本使用 utf8mb4；连接池上限是进程级保护，重工具并发另由 job slot 控制。
	dsnConfig := mysql.Config{
		User:                 cfg.User,
		Passwd:               cfg.Password,
		Net:                  "tcp",
		Addr:                 net.JoinHostPort(cfg.Host, cfg.Port),
		DBName:               cfg.Name,
		ParseTime:            true,
		Loc:                  time.UTC,
		Collation:            "utf8mb4_0900_ai_ci",
		AllowNativePasswords: true,
		MultiStatements:      true,
	}
	dsn := dsnConfig.FormatDSN()

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	db.SetMaxOpenConns(30)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(15 * time.Minute)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return db, nil
}

func Migrate(ctx context.Context, db *sql.DB, migrationFS fs.FS) error {
	// MySQL advisory lock 保证多个容器同时冷启动时只有一个实例迁移；每个编号 SQL 与
	// schema_migrations 记录在同一事务提交，失败不会留下“脚本已改、版本未记”的半状态。
	var locked int
	if err := db.QueryRowContext(ctx, "SELECT GET_LOCK('binaryscan_schema_migration', 30)").Scan(&locked); err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}
	if locked != 1 {
		return fmt.Errorf("migration lock was not acquired")
	}
	defer db.ExecContext(context.Background(), "SELECT RELEASE_LOCK('binaryscan_schema_migration')")

	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
        version BIGINT UNSIGNED NOT NULL PRIMARY KEY,
        applied_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci`); err != nil {
		return fmt.Errorf("create migration table: %w", err)
	}

	entries, err := fs.ReadDir(migrationFS, ".")
	if err != nil {
		return fmt.Errorf("list migrations: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		prefix, _, ok := strings.Cut(entry.Name(), "_")
		if !ok {
			return fmt.Errorf("migration filename %q has no numeric prefix", entry.Name())
		}
		version, err := strconv.ParseUint(prefix, 10, 64)
		if err != nil {
			return fmt.Errorf("parse migration version %q: %w", entry.Name(), err)
		}
		var exists int
		if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_migrations WHERE version = ?", version).Scan(&exists); err != nil {
			return fmt.Errorf("check migration %d: %w", version, err)
		}
		if exists != 0 {
			continue
		}
		body, err := fs.ReadFile(migrationFS, entry.Name())
		if err != nil {
			return fmt.Errorf("read migration %q: %w", entry.Name(), err)
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin migration %d: %w", version, err)
		}
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			tx.Rollback()
			return fmt.Errorf("apply migration %d: %w", version, err)
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO schema_migrations (version) VALUES (?)", version); err != nil {
			tx.Rollback()
			return fmt.Errorf("record migration %d: %w", version, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %d: %w", version, err)
		}
	}
	return nil
}
