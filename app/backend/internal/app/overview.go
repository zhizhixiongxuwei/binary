package app

import (
	"database/sql"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/gin-gonic/gin"
)

type overviewBucket struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}
type overviewDay struct {
	Date    string `json:"date"`
	Created int    `json:"created"`
	Failed  int    `json:"failed"`
}
type overviewFailure struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}
type overviewSummary struct {
	CreatedFrom string            `json:"created_from"`
	CreatedTo   string            `json:"created_to"`
	CollectedAt time.Time         `json:"collected_at"`
	Total       int               `json:"total"`
	Active      int               `json:"active"`
	Queued      int               `json:"queued"`
	Failed      int               `json:"failed"`
	Trend       []overviewDay     `json:"trend"`
	Statuses    []overviewBucket  `json:"statuses"`
	Formats     []overviewBucket  `json:"formats"`
	Failures    []overviewFailure `json:"failures"`
}

// Use the same visibility as the task list, including its exclusion of archive batches.
const overviewVisible = `deleted_at IS NULL AND COALESCE(analysis_mode, input_category, 'binary') <> 'archive'`

func overviewWindow(now time.Time, days int) overviewSummary {
	now = now.UTC()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	start := today.AddDate(0, 0, 1-days)
	result := overviewSummary{CreatedFrom: start.Format(time.DateOnly), CreatedTo: today.Format(time.DateOnly),
		CollectedAt: now, Trend: []overviewDay{}, Statuses: []overviewBucket{}, Formats: []overviewBucket{}, Failures: []overviewFailure{}}
	for day := start; !day.After(today); day = day.AddDate(0, 0, 1) {
		result.Trend = append(result.Trend, overviewDay{Date: day.Format(time.DateOnly)})
	}
	return result
}

func (s *taskService) overview(c *gin.Context) {
	days := 7
	switch c.DefaultQuery("days", "7") {
	case "7":
	case "30":
		days = 30
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_overview_window"})
		return
	}
	result, err := s.collectOverview(c, time.Now(), days)
	if err != nil {
		_ = c.Error(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "overview_query_failed"})
		return
	}
	c.JSON(http.StatusOK, result)
}

func (s *taskService) collectOverview(c *gin.Context, now time.Time, days int) (overviewSummary, error) {
	result := overviewWindow(now, days)
	// All cards and charts come from one consistent database snapshot.
	tx, err := s.db.BeginTx(c.Request.Context(), &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(c, `SELECT status, COUNT(*) FROM tasks WHERE `+overviewVisible+` AND status IN ('queued','scanning') GROUP BY status`)
	if err != nil {
		return result, err
	}
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			rows.Close()
			return result, err
		}
		if status == "queued" {
			result.Queued = count
		} else {
			result.Active = count
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return result, err
	}
	start, _ := time.Parse(time.DateOnly, result.CreatedFrom)
	rows, err = tx.QueryContext(c, `SELECT DATE_FORMAT(created_at, '%Y-%m-%d'), status,
  LOWER(COALESCE(NULLIF(detected_format, ''), 'unknown')), COUNT(*) FROM tasks WHERE `+overviewVisible+`
  AND created_at >= ? AND created_at <= ? GROUP BY DATE_FORMAT(created_at, '%Y-%m-%d'), status,
  LOWER(COALESCE(NULLIF(detected_format, ''), 'unknown'))`, start, now.UTC())
	if err != nil {
		return result, err
	}
	statuses, formats := map[string]int{}, map[string]int{}
	for rows.Next() {
		var day, status, format string
		var count int
		if err := rows.Scan(&day, &status, &format, &count); err != nil {
			rows.Close()
			return result, err
		}
		result.Total += count
		statuses[status] += count
		formats[format] += count
		if status == "failed" {
			result.Failed += count
		}
		for i := range result.Trend {
			if result.Trend[i].Date == day {
				result.Trend[i].Created += count
				if status == "failed" {
					result.Trend[i].Failed += count
				}
				break
			}
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return result, err
	}
	// Stable ordering also keeps chart colors stable between refreshes.
	for _, status := range []string{"ready", "partial", "scanning", "queued", "failed", "deleting", "deleted"} {
		if count := statuses[status]; count > 0 {
			result.Statuses = append(result.Statuses, overviewBucket{Value: status, Count: count})
		}
	}
	for format, count := range formats {
		result.Formats = append(result.Formats, overviewBucket{Value: format, Count: count})
	}
	sort.Slice(result.Formats, func(i, j int) bool {
		if result.Formats[i].Count == result.Formats[j].Count {
			return result.Formats[i].Value < result.Formats[j].Value
		}
		return result.Formats[i].Count > result.Formats[j].Count
	})
	rows, err = tx.QueryContext(c, `SELECT id, display_name, created_at FROM tasks WHERE `+overviewVisible+`
  AND status = 'failed' AND created_at >= ? AND created_at <= ? ORDER BY created_at DESC, id DESC LIMIT 3`, start, now.UTC())
	if err != nil {
		return result, err
	}
	for rows.Next() {
		var item overviewFailure
		if err := rows.Scan(&item.ID, &item.Name, &item.CreatedAt); err != nil {
			rows.Close()
			return result, err
		}
		result.Failures = append(result.Failures, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return result, fmt.Errorf("overview failures: %w", err)
	}
	return result, tx.Commit()
}
