package scanner

import "testing"

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
