package jvmarchive

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var probeClass = []byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 61}

func jarBytes(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var body bytes.Buffer
	writer := zip.NewWriter(&body)
	for name, content := range entries {
		target, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := target.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return body.Bytes()
}

func fixture(t *testing.T, duplicate, multi bool) (string, string) {
	t.Helper()
	childEntries := map[string][]byte{"META-INF/maven/example/module/pom.properties": []byte("groupId=example\n"), "example/Module.class": probeClass}
	if duplicate {
		childEntries["example/Main.class"] = probeClass
	}
	if multi {
		childEntries["META-INF/versions/21/example/Module.class"] = probeClass
	}
	body := jarBytes(t, map[string][]byte{
		"META-INF/maven/example/app/pom.properties": []byte("groupId=example\n"),
		"BOOT-INF/classes/example/Main.class":       probeClass,
		"BOOT-INF/lib/firstparty.jar":               jarBytes(t, childEntries),
		"BOOT-INF/lib/not-firstparty.jar":           jarBytes(t, map[string][]byte{"META-INF/maven/vendor/lib/pom.properties": []byte("groupId=vendor\n"), "vendor/Dependency.class": probeClass}),
		"org/springframework/boot/Loader.class":     probeClass,
	})
	filename := filepath.Join(t.TempDir(), "app.jar")
	if err := os.WriteFile(filename, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return filename, fmt.Sprintf("%x", sha256.Sum256(body))
}

func TestPrepareSelectsMetadataAndPreservesModuleIdentity(t *testing.T) {
	filename, digest := fixture(t, false, false)
	p, err := Prepare(context.Background(), filename, t.TempDir(), Options{ExpectedSHA256: digest})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Targets) != 2 || len(p.Dependencies) != 1 || len(p.Scope.Modules) != 3 || p.Targets[1].EntryPath != "BOOT-INF/lib/firstparty.jar" || p.Scope.InputSHA256 != digest {
		t.Fatalf("wrong scope: %+v", p)
	}
	bundle := filepath.Join(t.TempDir(), "bundle.zip")
	if err := p.Bundle(context.Background(), bundle); err != nil {
		t.Fatal(err)
	}
	z, err := zip.OpenReader(bundle)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	if len(z.File) != 3 || z.File[0].Name != "targets/0000.jar" {
		t.Fatalf("bad bundle: %+v", z.File)
	}
	q, err := Prepare(context.Background(), filename, t.TempDir(), Options{ExpectedSHA256: digest, ApplicationGroups: []string{"vendor"}})
	if err != nil || len(q.Targets) != 2 || q.Targets[1].EntryPath != "BOOT-INF/lib/not-firstparty.jar" {
		t.Fatalf("explicit selection ignored: %+v, %v", q, err)
	}
}

func TestPrepareReportsAmbiguityAndRejectsTamperedOriginal(t *testing.T) {
	filename, digest := fixture(t, true, true)
	p, err := Prepare(context.Background(), filename, t.TempDir(), Options{ExpectedSHA256: digest})
	if err != nil {
		t.Fatal(err)
	}
	diagnostics := strings.Join(p.Scope.Diagnostics, "\n")
	if !strings.Contains(diagnostics, "Duplicate application class") || !strings.Contains(diagnostics, "multi-release") {
		t.Fatalf("ambiguity was hidden: %v", p.Scope.Diagnostics)
	}
	if _, err := Prepare(context.Background(), filename, t.TempDir(), Options{ExpectedSHA256: strings.Repeat("0", 64)}); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("changed input accepted: %v", err)
	}
}

func TestPrepareRejectsUnsafeNestedAndCumulativeExpansion(t *testing.T) {
	body := jarBytes(t, map[string][]byte{"BOOT-INF/classes/example/Main.class": probeClass, "BOOT-INF/lib/unsafe.jar": jarBytes(t, map[string][]byte{"../Escape.class": probeClass})})
	filename := filepath.Join(t.TempDir(), "app.jar")
	if err := os.WriteFile(filename, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(context.Background(), filename, t.TempDir(), Options{}); err == nil || !strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("unsafe nested path accepted: %v", err)
	}
	if _, err := boundedCopy(context.Background(), &bytes.Buffer{}, bytes.NewReader(make([]byte, 12)), 11); err == nil {
		t.Fatal("expansion limit ignored")
	}
}

func TestPrepareKeepsOrdinaryJARCompatibility(t *testing.T) {
	body := jarBytes(t, map[string][]byte{"sample/Probe.class": probeClass})
	filename := filepath.Join(t.TempDir(), "probe.jar")
	_ = os.WriteFile(filename, body, 0o600)
	called := false
	prepared, err := Prepare(context.Background(), filename, t.TempDir(), Options{OnProgress: func(_, _ int) { called = true }})
	if err != nil || prepared != nil {
		t.Fatalf("ordinary JAR changed: %+v, %v", prepared, err)
	}
	if called {
		t.Fatal("ordinary JAR reported Boot archive preparation")
	}
}

func TestPrepareReportsAllModulesIncludingUnselectedDependencies(t *testing.T) {
	filename, digest := fixture(t, false, false)
	var updates [][2]int
	prepared, err := Prepare(context.Background(), filename, t.TempDir(), Options{
		ExpectedSHA256: digest,
		OnProgress:     func(done, total int) { updates = append(updates, [2]int{done, total}) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared.Targets) != 2 || len(prepared.Dependencies) != 1 || len(updates) != 4 {
		t.Fatalf("preparation excluded dependency work: %+v; updates=%v", prepared, updates)
	}
	for index, update := range updates {
		if update != [2]int{index, 3} {
			t.Fatalf("non-monotonic or invented module counters: %v", updates)
		}
	}
}

func TestPrepareCancellationDoesNotReportUnfinishedModules(t *testing.T) {
	filename, digest := fixture(t, false, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var last, totalSeen int
	_, err := Prepare(ctx, filename, t.TempDir(), Options{
		ExpectedSHA256: digest,
		OnProgress: func(done, total int) {
			last, totalSeen = done, total
			if done == 1 {
				cancel()
			}
		},
	})
	if err != context.Canceled || last != 1 || totalSeen != 3 {
		t.Fatalf("cancelled preparation reported unfinished work: done=%d total=%d err=%v", last, totalSeen, err)
	}
}

func TestMultiReleaseUsesHighestDeclaredJava21Class(t *testing.T) {
	base := []byte{0xca, 0xfe, 0xba, 0xbe, 8}
	selected := []byte{0xca, 0xfe, 0xba, 0xbe, 21}
	inner := jarBytes(t, map[string][]byte{
		"META-INF/MANIFEST.MF":                    []byte("Manifest-Version: 1.0\r\nMulti-Release: true\r\n\r\n"),
		"sample/Probe.class":                      base,
		"META-INF/versions/17/sample/Probe.class": append(append([]byte{}, base...), 17),
		"META-INF/versions/21/sample/Probe.class": selected,
		"META-INF/versions/22/sample/Probe.class": append(append([]byte{}, base...), 22),
	})
	filename := filepath.Join(t.TempDir(), "mr.jar")
	if err := os.WriteFile(filename, inner, 0o600); err != nil {
		t.Fatal(err)
	}
	jar, err := zip.OpenReader(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer jar.Close()
	output := filepath.Join(t.TempDir(), "normalized.jar")
	b := &budget{}
	count, err := classJar(context.Background(), jar.File, "", output, b)
	if err != nil || count != 1 || len(b.diagnostics) != 0 {
		t.Fatalf("bad multi-release selection: %d %v %v", count, err, b.diagnostics)
	}
	result, err := zip.OpenReader(output)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Close()
	source, err := result.File[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	var contents bytes.Buffer
	_, err = contents.ReadFrom(source)
	if err != nil || result.File[0].Name != "sample/Probe.class" || !bytes.Equal(contents.Bytes(), selected) {
		t.Fatalf("wrong effective class: %s %x %v", result.File[0].Name, contents.Bytes(), err)
	}
}

func TestBootClasspathIndexPreservesOrderAndDiagnosesUnsupportedIndex(t *testing.T) {
	for _, test := range []struct {
		name, index, policy string
		invalid             bool
	}{
		{"valid", "- \"BOOT-INF/lib/z.jar\"\n- \"BOOT-INF/lib/a.jar\"\n", "boot-classpath-index", false},
		{"incomplete", "- \"BOOT-INF/lib/a.jar\"\n", "zip-central-directory-order-fallback", true},
		{"duplicate", "- \"BOOT-INF/lib/a.jar\"\n- \"BOOT-INF/lib/a.jar\"\n", "zip-central-directory-order-fallback", true},
		{"unsupported-yaml", "- BOOT-INF/lib/z.jar\n- BOOT-INF/lib/a.jar\n", "zip-central-directory-order-fallback", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := jarBytes(t, map[string][]byte{
				"META-INF/maven/example/app/pom.properties": []byte("groupId=example\n"),
				"BOOT-INF/classes/example/Main.class":       probeClass,
				"BOOT-INF/classpath.idx":                    []byte(test.index),
				"BOOT-INF/lib/a.jar":                        jarBytes(t, map[string][]byte{"vendor/A.class": probeClass}),
				"BOOT-INF/lib/z.jar":                        jarBytes(t, map[string][]byte{"vendor/Z.class": probeClass}),
			})
			filename := filepath.Join(t.TempDir(), "app.jar")
			if err := os.WriteFile(filename, body, 0o600); err != nil {
				t.Fatal(err)
			}
			prepared, err := Prepare(context.Background(), filename, t.TempDir(), Options{})
			if err != nil {
				t.Fatal(err)
			}
			if prepared.Scope.ClasspathOrder != test.policy || prepared.Scope.ClasspathIndexSHA256 == "" {
				t.Fatalf("index policy not recorded: %+v", prepared.Scope)
			}
			if test.invalid {
				if !strings.Contains(strings.Join(prepared.Scope.Diagnostics, " "), "runtime precedence is not verified") {
					t.Fatal("unsupported classpath index silently ignored")
				}
				outer, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
				if err != nil {
					t.Fatal(err)
				}
				var expected []string
				for _, entry := range outer.File {
					if strings.HasPrefix(entry.Name, "BOOT-INF/lib/") {
						expected = append(expected, entry.Name)
					}
				}
				for index, unit := range prepared.Dependencies {
					if unit.EntryPath != expected[index] {
						t.Fatalf("fallback reordered ZIP entries: %v", prepared.Dependencies)
					}
				}
			} else if prepared.Dependencies[0].EntryPath != "BOOT-INF/lib/z.jar" || prepared.Dependencies[1].EntryPath != "BOOT-INF/lib/a.jar" {
				t.Fatalf("valid index precedence changed: %v", prepared.Dependencies)
			}
		})
	}
}

func TestEffectiveDependencyClassConflictsAreContentCheckedAndBounded(t *testing.T) {
	for _, identical := range []bool{true, false} {
		t.Run(fmt.Sprintf("identical=%t", identical), func(t *testing.T) {
			first, second := map[string][]byte{}, map[string][]byte{}
			for index := 0; index < 105; index++ {
				name := fmt.Sprintf("vendor/Duplicate%03d.class", index)
				first[name] = probeClass
				second[name] = append([]byte{}, probeClass...)
				if !identical {
					second[name] = append(second[name], 1)
				}
			}
			body := jarBytes(t, map[string][]byte{
				"META-INF/maven/example/app/pom.properties": []byte("groupId=example\n"),
				"BOOT-INF/classes/example/Main.class":       probeClass,
				"BOOT-INF/lib/first.jar":                    jarBytes(t, first),
				"BOOT-INF/lib/second.jar":                   jarBytes(t, second),
			})
			filename := filepath.Join(t.TempDir(), "app.jar")
			if err := os.WriteFile(filename, body, 0o600); err != nil {
				t.Fatal(err)
			}
			prepared, err := Prepare(context.Background(), filename, t.TempDir(), Options{})
			if err != nil {
				t.Fatal(err)
			}
			if prepared.Scope.ClasspathOrder != "zip-central-directory-order" {
				t.Fatalf("missing-index strategy was not declared: %+v", prepared.Scope)
			}
			if identical {
				if len(prepared.Scope.Diagnostics) != 0 {
					t.Fatalf("identical dependency class content was flagged as conflict: %v", prepared.Scope.Diagnostics)
				}
			} else if len(prepared.Scope.Diagnostics) != 100 || !prepared.Scope.DiagnosticsTruncated || !strings.Contains(prepared.Scope.Diagnostics[0], "Conflicting effective class") {
				t.Fatalf("conflicts not bounded/recorded: %+v", prepared.Scope)
			}
		})
	}
}

// Opt-in verification against an authorized local artifact; never launches it.
func TestWMSArchivePreparation(t *testing.T) {
	filename := os.Getenv("BINARY_TEST_WMS_JAR")
	if filename == "" {
		t.Skip("BINARY_TEST_WMS_JAR not set")
	}
	p, err := Prepare(context.Background(), filename, t.TempDir(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if p == nil {
		t.Fatal("expected Spring Boot JAR")
	}
	if err := p.Bundle(context.Background(), filepath.Join(t.TempDir(), "wms.zip")); err != nil {
		t.Fatal(err)
	}
	t.Logf("application modules=%d dependencies=%d classpath=%s diagnostics=%v", len(p.Targets), len(p.Dependencies), p.Scope.ClasspathOrder, p.Scope.Diagnostics)
}
