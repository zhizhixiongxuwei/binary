package app

import (
	"net/url"
	"testing"
	"time"
)

func TestParseTaskListOptionsPreservesPaginationAndFilters(t *testing.T) {
	values := url.Values{
		"page_size":    {"20"},
		"cursor":       {"11111111-1111-4111-8111-111111111111"},
		"keyword":      {"vulnerable"},
		"status":       {"SUCCEEDED"},
		"input_type":   {"ELF64"},
		"creator":      {"admin"},
		"tag":          {"ELF64"},
		"created_from": {"2026-08-01"},
		"created_to":   {"2026-08-27"},
	}

	options, err := parseTaskListOptions(values)
	if err != nil {
		t.Fatal(err)
	}
	if options.PageSize != 20 || options.Cursor != values.Get("cursor") {
		t.Fatalf("unexpected page options: %#v", options)
	}
	if options.Keyword != "vulnerable" || options.Status != "ready" || options.InputType != "elf64" {
		t.Fatalf("unexpected primary filters: %#v", options)
	}
	if options.Creator != "admin" || options.Tag != "ELF64" {
		t.Fatalf("unexpected advanced filters: %#v", options)
	}
	if options.CreatedFrom == nil || !options.CreatedFrom.Equal(time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("unexpected created_from: %#v", options.CreatedFrom)
	}
	if options.CreatedTo == nil || !options.CreatedTo.Equal(time.Date(2026, 8, 28, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("unexpected exclusive created_to: %#v", options.CreatedTo)
	}
}

func TestParseTaskListOptionsRejectsInvalidPaginationAndFilters(t *testing.T) {
	tests := []url.Values{
		{"page_size": {"0"}},
		{"page_size": {"101"}},
		{"status": {"unknown-status"}},
		{"created_from": {"2026-02-30"}},
		{"created_from": {"2026-08-28"}, "created_to": {"2026-08-27"}},
		{"keyword": {"unsafe\nvalue"}},
	}
	for _, values := range tests {
		if _, err := parseTaskListOptions(values); err == nil {
			t.Fatalf("expected invalid query to fail: %v", values)
		}
	}
}

func TestTaskListStatusMapsVisibleLifecycleStates(t *testing.T) {
	tests := map[string]string{
		"QUEUED":            "queued",
		"SCANNING":          "scanning",
		"EXTRACTING":        "scanning",
		"SUCCEEDED":         "ready",
		"PARTIAL_SUCCEEDED": "partial",
		"FAILED":            "failed",
		"DELETING":          "deleting",
		"CANCELLED":         "__no_matching_status__",
	}
	for input, expected := range tests {
		actual, err := taskListStatus(input)
		if err != nil {
			t.Fatalf("status %q failed: %v", input, err)
		}
		if actual != expected {
			t.Fatalf("status %q = %q, want %q", input, actual, expected)
		}
	}
}
