package scanner

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"binaryscan.local/backend/internal/config"
	"binaryscan.local/backend/internal/storage"
)

func TestCheckerSourceProjectFileLimit(t *testing.T) {
	for _, test := range []struct {
		kind     string
		language string
		limit    int
	}{
		{kind: "jvm", language: "java", limit: storage.MaxJVMSourceFiles},
		{kind: "native", language: "c", limit: storage.MaxSourceFiles},
		{kind: "pyc", language: "python", limit: storage.MaxSourceFiles},
	} {
		t.Run(test.kind, func(t *testing.T) {
			root := t.TempDir()
			executor := Executor{cfg: config.Config{Worker: config.Worker{ProjectRoot: root}}}
			project := checkerProject{
				id: "project", decompileRunID: "run", sourceKind: test.kind, language: test.language,
				storageKey: "project",
			}
			projectRoot := filepath.Join(root, project.sourceKind, project.storageKey)
			if err := os.MkdirAll(projectRoot, 0o700); err != nil {
				t.Fatal(err)
			}
			for _, count := range []int{test.limit, test.limit + 1} {
				manifest := storage.Manifest{
					Version: "project-v2", ProjectID: project.id, RunID: project.decompileRunID,
					Language: project.language, Files: make([]storage.ManifestFile, count),
				}
				body, err := json.Marshal(manifest)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(projectRoot, "project.json"), body, 0o600); err != nil {
					t.Fatal(err)
				}
				digest := sha256.Sum256(body)
				project.manifestSHA256 = digest[:]
				_, loaded, err := executor.openProject(project)
				if count == test.limit && (err != nil || len(loaded.Files) != count) {
					t.Fatalf("project with %d files was not accepted: %v", count, err)
				}
				if count > test.limit && err == nil {
					t.Fatalf("project with %d files was accepted above the limit of %d", count, test.limit)
				}
			}
		})
	}
}

func TestSourceSnippetKeepsOriginalLineNumbers(t *testing.T) {
	lines := []string{"one", "two", "danger()", "four", "five", "six"}
	snippet, start := sourceSnippet(lines, 3, 2)
	if start != 1 || snippet != "one\ntwo\ndanger()\nfour\nfive" {
		t.Fatalf("unexpected snippet start=%d body=%q", start, snippet)
	}
}

func TestSourceSnippetBoundsAtEnd(t *testing.T) {
	lines := []string{"one", "two", "three"}
	snippet, start := sourceSnippet(lines, 3, 2)
	if start != 1 || snippet != "one\ntwo\nthree" {
		t.Fatalf("unexpected snippet start=%d body=%q", start, snippet)
	}
}

func TestUTF16FindingRangeMatchesMonacoColumns(t *testing.T) {
	line := "中😀文 eval(value)"
	prefix := "中😀文 "
	startColumn := utf16CodeUnitCount(prefix) + 1
	endColumn, ok := utf16FindingEndColumn(line, startColumn)
	if !ok {
		t.Fatal("expected the ASCII finding after Unicode text to be valid")
	}
	if startColumn != 6 || endColumn != 7 {
		t.Fatalf("unexpected Monaco range %d:%d", startColumn, endColumn)
	}
	if maxColumn := utf16CodeUnitCount(line) + 1; maxColumn != 17 {
		t.Fatalf("unexpected Monaco max column %d", maxColumn)
	}
}

func TestUTF16FindingRangeSpansSupplementaryCharacter(t *testing.T) {
	endColumn, ok := utf16FindingEndColumn("中😀文", 2)
	if !ok || endColumn != 4 {
		t.Fatalf("emoji end column = %d, valid = %t; want 4, true", endColumn, ok)
	}
	if _, ok := utf16FindingEndColumn("中😀文", 6); ok {
		t.Fatal("expected a column beyond the UTF-16 line length to be rejected")
	}
	if _, ok := utf16FindingEndColumn("😀", 2); ok {
		t.Fatal("expected a column between UTF-16 surrogate halves to be rejected")
	}
	if endColumn, ok := utf16FindingEndColumn("😀", 3); !ok || endColumn != 3 {
		t.Fatalf("end-of-line column = %d, valid = %t; want 3, true", endColumn, ok)
	}
}
