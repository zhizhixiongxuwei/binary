package app

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func TestReadableReportsUseBusinessLabelsAndPreserveRawSnapshot(t *testing.T) {
	runs := []map[string]any{
		{"kind": "trivy_scan", "toolName": "trivy", "toolVersion": "0.72.0"},
		{"kind": "native_decompile", "toolName": "Ghidra", "toolVersion": "12.1"},
		{"kind": "jvm_decompile", "toolName": "vineflower", "toolVersion": "vineflower-1.11+cfr-0.152+jadx-1.5"},
		{"kind": "jvm_decompile", "toolName": "cfr", "toolVersion": "0.152"},
		{"kind": "jvm_decompile", "toolName": "jadx", "toolVersion": "1.5"},
		{"kind": "pyc_decompile", "toolName": "pycdc", "toolVersion": "unknown"},
	}
	snapshot := map[string]any{"task": map[string]any{"displayName": "sample"}, "runs": runs,
		"summary": buildReportSummary(runs, nil), "findings": []map[string]any{}}
	original, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	html := string(buildHTMLReport(snapshot))
	docx, err := buildDOCXReport(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := zip.NewReader(bytes.NewReader(docx), int64(len(docx)))
	if err != nil {
		t.Fatal(err)
	}
	document := ""
	for _, file := range archive.File {
		if file.Name != "word/document.xml" {
			continue
		}
		reader, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(reader)
		reader.Close()
		if err != nil {
			t.Fatal(err)
		}
		document = string(body)
	}
	if document == "" {
		t.Fatal("DOCX document is missing")
	}
	for _, output := range []string{html, document} {
		for _, name := range []string{"trivy", "ghidra", "vineflower", "cfr", "jadx", "pycdc"} {
			if strings.Contains(strings.ToLower(output), name) {
				t.Fatalf("readable report exposes engine identifier %q", name)
			}
		}
		for _, label := range []string{"漏洞检测引擎", "原生二进制反编译引擎", "Java 反编译引擎", "Android 反编译引擎", "Python 字节码反编译引擎"} {
			if !strings.Contains(output, label) {
				t.Fatalf("readable report omitted %q", label)
			}
		}
	}
	after, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, after) {
		t.Fatal("rendering modified the raw report snapshot")
	}
	if !bytes.Contains(after, []byte("vineflower-1.11+cfr-0.152+jadx-1.5")) {
		t.Fatal("original component versions were lost")
	}
}
