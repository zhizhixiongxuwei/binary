package app

import (
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"
)

type taskRunRowStub struct {
	created time.Time
}

func (row taskRunRowStub) Scan(dest ...any) error {
	if len(dest) != 14 {
		return fmt.Errorf("scan destination count = %d, want 14", len(dest))
	}
	*dest[0].(*string) = "run-1"
	*dest[1].(*string) = "java_check"
	*dest[2].(*string) = "complete"
	*dest[3].(*string) = "source_project"
	*dest[4].(*string) = "project-1"
	*dest[5].(*sql.NullString) = sql.NullString{String: "source", Valid: true}
	*dest[6].(*sql.NullString) = sql.NullString{String: "java-checker", Valid: true}
	*dest[7].(*sql.NullString) = sql.NullString{String: "1.0.0", Valid: true}
	*dest[8].(*sql.NullString) = sql.NullString{String: "checker-v1", Valid: true}
	*dest[9].(*sql.NullString) = sql.NullString{}
	*dest[10].(*sql.NullString) = sql.NullString{}
	*dest[11].(*time.Time) = row.created
	*dest[12].(*sql.NullTime) = sql.NullTime{Time: row.created, Valid: true}
	*dest[13].(*sql.NullTime) = sql.NullTime{Time: row.created.Add(time.Second), Valid: true}
	return nil
}

func TestScanTaskRunIncludesRulesetVersion(t *testing.T) {
	t.Parallel()
	if !strings.Contains(taskRunsQuery, "tool_version, ruleset_version") {
		t.Fatal("task run query does not select ruleset_version after tool_version")
	}

	created := time.Date(2026, time.August, 24, 10, 0, 0, 0, time.UTC)
	run, err := scanTaskRun(taskRunRowStub{created: created})
	if err != nil {
		t.Fatal(err)
	}
	if actual := run["rulesetVersion"]; actual != "checker-v1" {
		t.Fatalf("rulesetVersion = %#v, want checker-v1", actual)
	}
	if actual := run["toolVersion"]; actual != "1.0.0" {
		t.Fatalf("toolVersion = %#v, want 1.0.0", actual)
	}
}
