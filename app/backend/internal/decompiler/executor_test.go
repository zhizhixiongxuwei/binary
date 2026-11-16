package decompiler

import (
	"binaryscan.local/backend/internal/config"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestJVMInputExtension(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"class":      "class",
		"java-class": "class",
		"jar":        "jar",
		"war":        "war",
		"ear":        "ear",
		"dex":        "dex",
		"apk":        "apk",
		"unknown":    "bin",
	}
	for format, want := range tests {
		format, want := format, want
		t.Run(format, func(t *testing.T) {
			t.Parallel()
			if got := jvmInputExtension(format); got != want {
				t.Fatalf("jvmInputExtension(%q) = %q, want %q", format, got, want)
			}
		})
	}
}

// Opt-in end-to-end decompilation against the installed tools. The original
// application is never started and all generated files stay in t.TempDir().
func TestWMSModuleDecompilation(t *testing.T) {
	input := os.Getenv("BINARY_TEST_WMS_JAR")
	if input == "" {
		t.Skip("BINARY_TEST_WMS_JAR not set")
	}
	executable := os.Getenv("BINARY_TEST_JAVA_PATH")
	if executable == "" {
		executable = "/opt/java/openjdk/bin/java"
	}
	vineflower := os.Getenv("BINARY_TEST_VINEFLOWER_JAR")
	if vineflower == "" {
		vineflower = "/opt/bytecode-tools/vineflower/vineflower.jar"
	}
	cfr := os.Getenv("BINARY_TEST_CFR_JAR")
	if cfr == "" {
		cfr = "/opt/bytecode-tools/cfr/cfr.jar"
	}
	e := &Executor{cfg: config.Config{Worker: config.Worker{JavaPath: executable, VineflowerJar: vineflower, CFRJar: cfr}}}
	result, err := e.runJVMArchive(context.Background(), t.TempDir(), input, "jar", "")
	if err != nil {
		t.Fatal(err)
	}
	if result.jvmArchive == nil {
		t.Fatal("module origin manifest missing")
	}
	var selected, sourceCount, librarySources int
	for _, module := range result.jvmArchive.Modules {
		if module.Role == "application" && module.ClassCount > 0 {
			selected++
		}
	}
	err = filepath.WalkDir(result.outputRoot, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && strings.HasSuffix(path, ".java") {
			sourceCount++
			if strings.Contains(filepath.ToSlash(path), "/modules/") {
				librarySources++
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if selected != 21 || sourceCount < 500 || librarySources < 350 {
		t.Fatalf("incomplete module outputs: selected=%d sources=%d nested=%d diagnostics=%v", selected, sourceCount, librarySources, result.jvmArchive.Diagnostics)
	}
	t.Logf("selected=%d sources=%d nested=%d quality=%s diagnostics=%v", selected, sourceCount, librarySources, result.quality, result.jvmArchive.Diagnostics)
}
