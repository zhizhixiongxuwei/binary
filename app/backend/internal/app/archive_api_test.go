package app

import (
	"database/sql"
	"testing"

	"binaryscan.local/backend/internal/job"
)

func TestMapArchiveEntryEligibility(t *testing.T) {
	sha := sql.NullString{String: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Valid: true}
	tests := []struct {
		name       string
		format     string
		stored     string
		created    string
		status     string
		category   string
		skipReason bool
	}{
		{name: "binary eligible", format: "elf64", stored: "materialized", status: "eligible", category: "binary"},
		{name: "binary created", format: "java-class", stored: "task_created", created: "task-id", status: "created", category: "binary"},
		{name: "container listed but not eligible", format: "docker-tar", stored: "materialized", status: "skipped", category: "container", skipReason: true},
		{name: "nested archive skipped", format: "zip", stored: "materialized", status: "skipped", skipReason: true},
		{name: "unknown skipped", format: "unknown", stored: "materialized", status: "skipped", skipReason: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entry := mapArchiveEntry(1, "member", 64, sha,
				sql.NullString{String: test.format, Valid: true}, test.stored,
				sql.NullString{String: test.created, Valid: test.created != ""})
			if entry.Status != test.status {
				t.Fatalf("status = %q, want %q", entry.Status, test.status)
			}
			if test.category == "" {
				if entry.DetectedCategory != nil {
					t.Fatalf("detected category = %q, want nil", *entry.DetectedCategory)
				}
			} else if entry.DetectedCategory == nil || *entry.DetectedCategory != test.category {
				t.Fatalf("detected category = %v, want %q", entry.DetectedCategory, test.category)
			}
			if test.skipReason && entry.SkipReason == "" {
				t.Fatal("expected a skip reason")
			}
		})
	}
}

func TestCanonicalDecompileAndArchiveRouting(t *testing.T) {
	for _, format := range []string{"pe32", "pe32+", "elf32", "elf64", "macho-thin", "macho-fat"} {
		kind, ok := decompileKind(format)
		if !ok || kind != job.KindNativeDecompile {
			t.Fatalf("decompileKind(%q) = %q, %v", format, kind, ok)
		}
	}
	for _, format := range []string{"java-class", "jar", "dex", "apk"} {
		kind, ok := decompileKind(format)
		if !ok || kind != job.KindJVMDecompile {
			t.Fatalf("decompileKind(%q) = %q, %v", format, kind, ok)
		}
	}
	for _, format := range []string{"pe", "elf", "mach-o", "macho", "class", "war", "ear"} {
		if _, ok := decompileKind(format); !ok {
			t.Fatalf("legacy decompileKind(%q) is not supported", format)
		}
	}
	for _, format := range []string{"zip", "7z", "rar", "tar", "gzip", "xz", "deb", "rpm", "iso9660", "ext4", "jar", "apk", "docker-tar", "oci-tar"} {
		if !archiveImportSupported(format) {
			t.Fatalf("archiveImportSupported(%q) = false", format)
		}
	}
}

func TestArchiveImportStatusPreservesUnsupported(t *testing.T) {
	t.Parallel()
	for input, want := range map[string]string{
		"queued": "queued", "running": "running", "complete": "ready", "partial": "ready",
		"unsupported": "unsupported", "failed": "failed", "cancelled": "failed",
	} {
		if actual := archiveImportStatus(input); actual != want {
			t.Errorf("archiveImportStatus(%q) = %q, want %q", input, actual, want)
		}
	}
}
