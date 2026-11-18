package app

import (
	"binaryscan.local/backend/internal/impact"
	"context"
	"log/slog"
	"time"
)

func (s *Server) MaintainSCA(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		check, cancel := context.WithTimeout(ctx, 20*time.Second)
		e := (impact.Store{DB: s.tasks.db}).Maintain(check)
		cancel()
		if e != nil && ctx.Err() == nil {
			slog.Warn("SCA evidence maintenance failed", "error", e)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
