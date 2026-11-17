package job

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestNestedArchiveProgressPreservesModuleAndClassCounters(t *testing.T) {
	var actual Progress
	ctx := WithProgressSink(context.Background(), func(value Progress) { actual = value })
	ctx = WithModuleProgress(ctx, 3, 21, "BOOT-INF/lib/business.jar")
	ReportProgress(ctx, "decompiling", 7, 20, "classes")
	if actual.Current != 7 || actual.Total != 20 || actual.ModuleCurrent != 3 || actual.ModuleTotal != 21 || actual.ModulePath != "BOOT-INF/lib/business.jar" {
		t.Fatalf("lost nested counters: %+v", actual)
	}
}

func TestFirstArchiveModuleRetainsZeroCompletedModuleCounter(t *testing.T) {
	var actual Progress
	ctx := WithProgressSink(context.Background(), func(value Progress) { actual = value })
	ctx = WithModuleProgress(ctx, 0, 21, "BOOT-INF/classes/")
	ReportProgress(ctx, "decompiling", 212, 212, "classes")
	body, err := json.Marshal(actual)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"module_current":0`) || !strings.Contains(string(body), `"module_total":21`) {
		t.Fatalf("first module was misrepresented as a complete archive: %s", body)
	}
}
