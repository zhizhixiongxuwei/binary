package decompiler

import (
	"context"
	"strings"
	"testing"

	"binaryscan.local/backend/internal/job"
)

func TestToolProgressHandlesChunkedPrefixedAndUntrustedLogs(t *testing.T) {
	var updates []job.Progress
	w := &toolProgressWriter{ctx: job.WithProgressSink(context.Background(), func(value job.Progress) { updates = append(updates, value) })}
	for _, body := range []string{
		"ordinary log\nINFO ExportPseudoC.java> BINARYSCAN_PRO",
		"GRESS decompiling 7 20 functions\r\n",
		"BINARYSCAN_PROGRESS decompiling -1 20 functions\n",
		"BINARYSCAN_PROGRESS decompiling 30 20 functions\n",
		"BINARYSCAN_PROGRESS decompiling 10 0 classes\n",
		"BINARYSCAN_PROGRESS decompiling 10 2000000 classes\n",
		strings.Repeat("x", 1025) + "BINARYSCAN_PROGRESS decompiling 1 2 classes\n",
		"BINARYSCAN_PROGRESS decompiling 20 20 classes\n",
	} {
		if written, err := w.Write([]byte(body)); written != len(body) || err != nil {
			t.Fatalf("short log write: %d, %v", written, err)
		}
	}
	if len(updates) != 2 || updates[0].Current != 7 || updates[0].Total != 20 || updates[0].Unit != "functions" || updates[1].Current != 20 {
		t.Fatalf("unexpected progress from tool logs: %+v", updates)
	}
}
