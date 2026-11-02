package app

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestOverviewWindowUTC(t *testing.T) {
	now, _ := time.Parse(time.RFC3339, "2026-11-03T01:00:00+08:00")
	for _, days := range []int{7, 30} {
		result := overviewWindow(now, days)
		if result.CreatedTo != "2026-11-02" || len(result.Trend) != days {
			t.Fatalf("unexpected window: %+v", result)
		}
		if days == 7 && result.CreatedFrom != "2026-10-27" {
			t.Fatal(result.CreatedFrom)
		}
		if days == 30 && result.CreatedFrom != "2026-10-04" {
			t.Fatal(result.CreatedFrom)
		}
		if result.Trend[0].Created != 0 || result.Trend[days-1].Date != result.CreatedTo {
			t.Fatal("window must include empty days")
		}
	}
}

func TestOverviewRejectsInvalidWindow(t *testing.T) {
	service := &taskService{}
	router := gin.New()
	router.GET("/overview", service.overview)
	for _, value := range []string{"0", "8", "365", "abc", ""} {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/overview?days="+value, nil))
		if response.Code != http.StatusBadRequest {
			t.Fatalf("days %q: %d", value, response.Code)
		}
	}
}

func TestOverviewFullDatabaseAggregation(t *testing.T) {
	service := cleanupTestService(t)
	cleanupBlob(t, service, "overview-blob")
	for i := 0; i < 12; i++ {
		id := fmt.Sprintf("overview-%02d", i)
		cleanupTask(t, service, id, "overview-blob", "", "binary")
		cleanupExec(t, service, `UPDATE tasks SET created_at='2026-11-02 01:00:00', status='failed', detected_format='elf64' WHERE id=?`, id)
	}
	for _, item := range []struct{ id, mode, status, date string }{
		{"old-active", "binary", "scanning", "2025-01-01"},
		{"old-queued", "binary", "queued", "2025-01-01"},
		{"archive", "archive", "failed", "2026-11-02"},
		{"outside", "binary", "failed", "2026-10-26 23:59:59"},
	} {
		cleanupTask(t, service, item.id, "overview-blob", "", item.mode)
		cleanupExec(t, service, `UPDATE tasks SET created_at=?, status=? WHERE id=?`, item.date, item.status, item.id)
	}
	router := gin.New()
	router.GET("/test", func(c *gin.Context) {
		now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
		result, err := service.collectOverview(c, now, 7)
		if err != nil {
			t.Error(err)
			c.Status(500)
			return
		}
		c.JSON(200, result)
	})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest("GET", "/test", nil))
	var result overviewSummary
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if response.Code != 200 || result.Total != 12 || result.Failed != 12 || result.Active != 1 || result.Queued != 1 {
		t.Fatalf("unexpected aggregate: %s", response.Body.String())
	}
	if len(result.Failures) != 3 || result.Trend[6].Failed != 12 || len(result.Formats) != 1 || result.Formats[0].Count != 12 {
		t.Fatalf("inconsistent charts: %+v", result)
	}
}
