// Package jvmarchive prepares bounded, reproducible Spring Boot analysis inputs.
// It never executes an archive or follows its manifest class path.
package jvmarchive

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	Version                = "boot-analysis-v1"
	MaxInputBytes    int64 = 256 << 20
	MaxExpandedBytes int64 = 768 << 20
	MaxBundleBytes   int64 = 112 << 20
	MaxTargetBytes   int64 = 32 << 20
	MaxEntries             = 120000
	MaxModules             = 512
)

type Module struct {
	EntryPath    string   `json:"entryPath"`
	SHA256       string   `json:"sha256"`
	Role         string   `json:"role"`
	GroupIDs     []string `json:"groupIds,omitempty"`
	ClassCount   int      `json:"classCount"`
	SourcePrefix string   `json:"sourcePrefix,omitempty"`
	SourceStatus string   `json:"sourceStatus,omitempty"`
	Decompiler   string   `json:"decompiler,omitempty"`
}

type Scope struct {
	Version              string   `json:"version"`
	InputSHA256          string   `json:"inputSha256"`
	Selection            string   `json:"selection"`
	ApplicationGroups    []string `json:"applicationGroups"`
	Modules              []Module `json:"modules"`
	Diagnostics          []string `json:"diagnostics"`
	TargetJavaRelease    int      `json:"targetJavaRelease"`
	ClasspathOrder       string   `json:"classpathOrder"`
	ClasspathIndexSHA256 string   `json:"classpathIndexSha256,omitempty"`
	DiagnosticsTruncated bool     `json:"diagnosticsTruncated,omitempty"`
}

type Options struct {
	ExpectedSHA256 string
	// nil derives the application groups from the outer Maven metadata.
	// A non-nil slice freezes an earlier project's selection, including empty.
	ApplicationGroups []string
	// OnProgress observes completed archive normalization work after a Boot
	// layout is confirmed. Total includes the root and every nested library,
	// including dependencies that will not be selected for decompilation.
	// Ordinary JARs do not invoke it. Nil preserves the existing behavior.
	OnProgress func(done, total int)
}

type Unit struct {
	Module
	Path string
}
type Prepared struct {
	Scope                 Scope
	Targets, Dependencies []Unit
}

// SameInputs ignores decompiler outcomes but binds the exact selected archives,
// bytecode release and roles to the already published source project's scope.
func (p *Prepared) SameInputs(expected *Scope) bool {
	if expected == nil || expected.Version != p.Scope.Version || expected.InputSHA256 != p.Scope.InputSHA256 || expected.TargetJavaRelease != p.Scope.TargetJavaRelease || expected.ClasspathOrder != p.Scope.ClasspathOrder || expected.ClasspathIndexSHA256 != p.Scope.ClasspathIndexSHA256 || len(expected.Modules) != len(p.Scope.Modules) {
		return false
	}
	for index, module := range p.Scope.Modules {
		other := expected.Modules[index]
		if module.EntryPath != other.EntryPath || module.SHA256 != other.SHA256 || module.Role != other.Role || module.ClassCount != other.ClassCount || module.SourcePrefix != other.SourcePrefix {
			return false
		}
	}
	return true
}

type budget struct {
	classDigests map[string]map[string]string
	bytes        int64
	entries      int
	diagnostics  []string
	truncated    bool
}

func (b *budget) diagnostic(message string) {
	if contains(b.diagnostics, message) {
		return
	}
	if len(b.diagnostics) == 100 {
		b.truncated = true
		return
	}
	b.diagnostics = append(b.diagnostics, message)
}

// GroupsFromEnvironment is deliberately explicit; archive/file names are not
// evidence of first-party ownership. The selected values are frozen in Scope.
func GroupsFromEnvironment() []string {
	value := strings.TrimSpace(os.Getenv("BINARY_JAVA_APPLICATION_GROUPS"))
	if value == "" {
		return nil
	}
	var groups []string
	for _, group := range strings.Split(value, ",") {
		if group = strings.TrimSpace(group); group != "" {
			groups = append(groups, group)
		}
	}
	return groups
}

func Verify(ctx context.Context, filename string, size int64, expected string) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("open original binary: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != size {
		return fmt.Errorf("original binary size does not match its blob record")
	}
	if size <= 0 || size > MaxInputBytes {
		return fmt.Errorf("original JAR exceeds the %d MiB preparation limit", MaxInputBytes>>20)
	}
	hash := sha256.New()
	buffer := make([]byte, 64<<10)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, readErr := file.Read(buffer)
		if n > 0 {
			_, _ = hash.Write(buffer[:n])
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	if expected != "" && !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), expected) {
		return fmt.Errorf("original binary digest does not match its blob record")
	}
	return nil
}

// Prepare returns nil for ordinary JARs. Inputs are fully hashed before ZIP
// inspection; caller-owned dir must be private and is removed by the caller.
func Prepare(ctx context.Context, filename, dir string, options Options) (*Prepared, error) {
	info, err := os.Stat(filename)
	if err != nil {
		return nil, err
	}
	if err := Verify(ctx, filename, info.Size(), options.ExpectedSHA256); err != nil {
		return nil, err
	}
	outer, err := zip.OpenReader(filename)
	if err != nil {
		return nil, fmt.Errorf("invalid JAR: %w", err)
	}
	defer outer.Close()
	if len(outer.File) > MaxEntries {
		return nil, fmt.Errorf("JAR entry limit exceeded")
	}
	boot := false
	for _, entry := range outer.File {
		if strings.HasPrefix(entry.Name, "BOOT-INF/classes/") && strings.HasSuffix(entry.Name, ".class") {
			boot = true
			break
		}
	}
	if !boot {
		return nil, nil
	}
	seen := make(map[string]bool)
	var libraries []*zip.File
	for _, entry := range outer.File {
		if !safeEntry(entry.Name) || seen[entry.Name] {
			return nil, fmt.Errorf("unsafe or duplicate JAR entry %q", entry.Name)
		}
		seen[entry.Name] = true
		if strings.HasPrefix(entry.Name, "BOOT-INF/lib/") && strings.HasSuffix(entry.Name, ".jar") {
			libraries = append(libraries, entry)
		}
	}
	if len(libraries) > MaxModules {
		return nil, fmt.Errorf("nested JAR module limit exceeded")
	}
	reportProgress := func(done int) {
		if options.OnProgress != nil {
			options.OnProgress(done, len(libraries)+1)
		}
	}
	reportProgress(0)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	b := &budget{}
	groups, err := mavenGroups(ctx, outer.File, "", b)
	if err != nil {
		return nil, err
	}
	classGroups, err := mavenGroups(ctx, outer.File, "BOOT-INF/classes/", b)
	if err != nil {
		return nil, err
	}
	groups = append(groups, classGroups...)
	selection := "outer-maven-group"
	if options.ApplicationGroups != nil {
		groups = append([]string{}, options.ApplicationGroups...)
		selection = "explicit-maven-groups"
	}
	groups = unique(groups)
	if len(groups) > 64 {
		return nil, fmt.Errorf("application Maven group limit exceeded")
	}
	for _, group := range groups {
		if len(group) > 256 || strings.IndexFunc(group, func(r rune) bool {
			return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '.' && r != '-' && r != '_'
		}) >= 0 {
			return nil, fmt.Errorf("invalid application Maven group")
		}
	}
	if len(groups) == 0 {
		b.diagnostic("Application Maven group is unavailable; nested modules are dependencies unless BINARY_JAVA_APPLICATION_GROUPS is configured")
	}
	inputSHA := options.ExpectedSHA256
	if inputSHA == "" {
		inputSHA = fileDigest(filename)
	}
	result := &Prepared{Scope: Scope{Version: Version, InputSHA256: inputSHA, Selection: selection, ApplicationGroups: groups, Modules: []Module{}, Diagnostics: []string{}, TargetJavaRelease: 21}}
	rootFile := filepath.Join(dir, "application.jar")
	count, err := classJar(ctx, outer.File, "BOOT-INF/classes/", rootFile, b)
	if err != nil {
		return nil, err
	}
	root := Module{EntryPath: "BOOT-INF/classes/", SHA256: fileDigest(rootFile), Role: "application", GroupIDs: groups, ClassCount: count, SourcePrefix: "application"}
	result.Targets = append(result.Targets, Unit{Module: root, Path: rootFile})
	result.Scope.Modules = append(result.Scope.Modules, root)
	reportProgress(1)
	libraries, result.Scope.ClasspathOrder, result.Scope.ClasspathIndexSHA256, err = orderLibraries(ctx, outer.File, libraries, b)
	if err != nil {
		return nil, err
	}
	for index, entry := range libraries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		raw := filepath.Join(dir, fmt.Sprintf("raw-%04d.jar", index))
		digest, err := extract(ctx, entry, raw, b)
		if err != nil {
			return nil, err
		}
		child, err := zip.OpenReader(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid nested JAR %s: %w", entry.Name, err)
		}
		childGroups, groupErr := mavenGroups(ctx, child.File, "", b)
		role := "dependency"
		prefix := ""
		for _, group := range childGroups {
			if contains(groups, group) {
				role = "application"
				prefix = fmt.Sprintf("modules/%04d", index)
				break
			}
		}
		prepared := filepath.Join(dir, fmt.Sprintf("module-%04d.jar", index))
		classCount, classErr := classJar(ctx, child.File, "", prepared, b)
		_ = child.Close()
		_ = os.Remove(raw)
		if groupErr != nil {
			return nil, groupErr
		}
		if classErr != nil {
			return nil, fmt.Errorf("%s: %w", entry.Name, classErr)
		}
		module := Module{EntryPath: entry.Name, SHA256: digest, Role: role, GroupIDs: childGroups, ClassCount: classCount, SourcePrefix: prefix}
		result.Scope.Modules = append(result.Scope.Modules, module)
		reportProgress(index + 2)
		if classCount == 0 {
			continue
		}
		unit := Unit{Module: module, Path: prepared}
		if role == "application" {
			result.Targets = append(result.Targets, unit)
		} else {
			result.Dependencies = append(result.Dependencies, unit)
		}
	}
	// The names below are the effective Java 21 entries after normalization.
	// This bounded check diagnoses differing class bytes; it does not attempt a
	// complete dependency resolver or claim the runtime's class-loader semantics.
	type definition struct{ module, digest, role string }
	classes := make(map[string]definition)
	units := append(append([]Unit{}, result.Targets...), result.Dependencies...)
	for _, unit := range units {
		// Hashes were computed over exactly the normalized bytes while writing
		// them. Reuse those pinned digests rather than inflating every dependency
		// a second time just to compare duplicate class identities.
		names := make([]string, 0, len(b.classDigests[unit.Path]))
		for name := range b.classDigests[unit.Path] {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			digest := b.classDigests[unit.Path][name]
			if previous, ok := classes[name]; ok {
				if previous.role == "application" && unit.Role == "application" {
					b.diagnostic("Duplicate application class " + name + " in " + previous.module + " and " + unit.EntryPath)
				} else if previous.digest != digest {
					b.diagnostic("Conflicting effective class " + name + " in " + previous.module + " and " + unit.EntryPath + "; class-loader resolution is not verified")
				}
			} else {
				classes[name] = definition{unit.EntryPath, digest, unit.Role}
			}
		}
	}
	result.Scope.Diagnostics = append([]string{}, b.diagnostics...)
	result.Scope.DiagnosticsTruncated = b.truncated
	return result, nil
}

// Spring Boot's standard index is a list of double-quoted archive paths, not
// arbitrary YAML. Accept only a complete exact list; unsupported or inconsistent
// input cannot silently alter precedence by being sorted or partially applied.
func orderLibraries(ctx context.Context, entries, libraries []*zip.File, b *budget) ([]*zip.File, string, string, error) {
	var index *zip.File
	for _, entry := range entries {
		if entry.Name == "BOOT-INF/classpath.idx" {
			index = entry
			break
		}
	}
	if index == nil {
		return libraries, "zip-central-directory-order", "", nil
	}
	if index.UncompressedSize64 > 64<<10 {
		b.diagnostic("BOOT-INF/classpath.idx exceeds supported 64 KiB size; ZIP central-directory order used and runtime precedence is not verified")
		return libraries, "zip-central-directory-order-fallback", "", nil
	}
	source, err := index.Open()
	if err != nil {
		return nil, "", "", err
	}
	var text strings.Builder
	n, copyErr := boundedCopy(ctx, &text, source, min(64<<10, MaxExpandedBytes-b.bytes))
	b.bytes += n
	closeErr := source.Close()
	if copyErr != nil {
		return nil, "", "", copyErr
	}
	if closeErr != nil {
		return nil, "", "", closeErr
	}
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(text.String())))
	fallback := func() ([]*zip.File, string, string, error) {
		b.diagnostic("BOOT-INF/classpath.idx is unsupported, incomplete or inconsistent; ZIP central-directory order used and runtime precedence is not verified")
		return libraries, "zip-central-directory-order-fallback", digest, nil
	}
	if !utf8.ValidString(text.String()) {
		return fallback()
	}
	byName := make(map[string]*zip.File, len(libraries))
	for _, library := range libraries {
		byName[library.Name] = library
	}
	ordered := make([]*zip.File, 0, len(libraries))
	seen := make(map[string]bool)
	for _, raw := range strings.Split(text.String(), "\n") {
		line := strings.TrimSuffix(raw, "\r")
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "- \"") || !strings.HasSuffix(line, "\"") {
			return fallback()
		}
		name := strings.TrimSuffix(strings.TrimPrefix(line, "- \""), "\"")
		if strings.ContainsAny(name, "\"\\") || !safeEntry(name) || seen[name] {
			return fallback()
		}
		library, ok := byName[name]
		if !ok {
			return fallback()
		}
		seen[name] = true
		ordered = append(ordered, library)
	}
	if len(ordered) != len(libraries) {
		return fallback()
	}
	return ordered, "boot-classpath-index", digest, nil
}

func classJar(ctx context.Context, entries []*zip.File, prefix, filename string, b *budget) (int, error) {
	if b.classDigests == nil {
		b.classDigests = map[string]map[string]string{}
	}
	b.classDigests[filename] = map[string]string{}
	if len(entries) > MaxEntries-b.entries {
		return 0, fmt.Errorf("cumulative JAR entry limit exceeded")
	}
	b.entries += len(entries)
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, err
	}
	writer := zip.NewWriter(file)
	count := 0
	seen := make(map[string]bool)
	defer file.Close()
	selected := make(map[string]*zip.File)
	releases := make(map[string]int)
	multiRelease := false
	if prefix == "" {
		for _, entry := range entries {
			if entry.Name != "META-INF/MANIFEST.MF" {
				continue
			}
			if entry.UncompressedSize64 > 1<<20 {
				return 0, fmt.Errorf("JAR manifest exceeds limit")
			}
			source, err := entry.Open()
			if err != nil {
				return 0, err
			}
			var manifest strings.Builder
			written, copyErr := boundedCopy(ctx, &manifest, source, min(1<<20, MaxExpandedBytes-b.bytes))
			b.bytes += written
			err = copyErr
			_ = source.Close()
			if err != nil {
				return 0, err
			}
			for _, line := range strings.Split(manifest.String(), "\n") {
				key, value, ok := strings.Cut(line, ":")
				if ok && strings.EqualFold(strings.TrimSpace(key), "Multi-Release") && strings.EqualFold(strings.TrimSpace(value), "true") {
					multiRelease = true
				}
			}
		}
	}
	for _, entry := range entries {
		if !safeEntry(entry.Name) || seen[entry.Name] {
			return 0, fmt.Errorf("unsafe or duplicate JAR entry %q", entry.Name)
		}
		seen[entry.Name] = true
		if !strings.HasPrefix(entry.Name, prefix) || entry.FileInfo().IsDir() {
			continue
		}
		name := strings.TrimPrefix(entry.Name, prefix)
		release := 0
		if strings.HasPrefix(name, "META-INF/versions/") && strings.HasSuffix(name, ".class") {
			version, base, ok := strings.Cut(strings.TrimPrefix(name, "META-INF/versions/"), "/")
			parsed, err := strconv.Atoi(version)
			if !multiRelease || !ok || err != nil || parsed < 9 {
				b.diagnostic("Unrecognized multi-release classes excluded from " + filepath.Base(filename))
				continue
			}
			if parsed > 21 {
				continue
			}
			name, release = base, parsed
		}
		if name == "module-info.class" {
			continue
		}
		if strings.HasSuffix(name, ".jar") && prefix == "" {
			b.diagnostic("Additional nested archive excluded: " + name)
			continue
		}
		if !strings.HasSuffix(name, ".class") {
			continue
		}
		if _, exists := selected[name]; !exists || release > releases[name] {
			selected[name] = entry
			releases[name] = release
		}
	}
	names := make([]string, 0, len(selected))
	for name := range selected {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		entry := selected[name]
		if entry.UncompressedSize64 > 4<<20 {
			return 0, fmt.Errorf("class entry exceeds 4 MiB")
		}
		source, err := entry.Open()
		if err != nil {
			return 0, err
		}
		magic := make([]byte, 4)
		if _, err := io.ReadFull(source, magic); err != nil || string(magic) != "\xca\xfe\xba\xbe" {
			_ = source.Close()
			return 0, fmt.Errorf("invalid JVM class entry %s", name)
		}
		destination, err := writer.Create(name)
		if err != nil {
			source.Close()
			return 0, err
		}
		hash := sha256.New()
		written, copyErr := boundedCopy(ctx, io.MultiWriter(destination, hash), io.MultiReader(strings.NewReader(string(magic)), source), MaxExpandedBytes-b.bytes)
		closeErr := source.Close()
		b.bytes += written
		if copyErr != nil {
			return 0, copyErr
		}
		if closeErr != nil {
			return 0, closeErr
		}
		if uint64(written) != entry.UncompressedSize64 {
			return 0, fmt.Errorf("class entry size mismatch")
		}
		b.classDigests[filename][name] = hex.EncodeToString(hash.Sum(nil))
		count++
	}
	if err := writer.Close(); err != nil {
		return 0, err
	}
	if err := file.Close(); err != nil {
		return 0, err
	}
	return count, nil
}

func extract(ctx context.Context, entry *zip.File, filename string, b *budget) (string, error) {
	if entry.UncompressedSize64 > uint64(MaxBundleBytes) {
		return "", fmt.Errorf("nested JAR exceeds module byte limit")
	}
	source, err := entry.Open()
	if err != nil {
		return "", err
	}
	defer source.Close()
	target, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	defer target.Close()
	hash := sha256.New()
	n, err := boundedCopy(ctx, io.MultiWriter(target, hash), source, MaxExpandedBytes-b.bytes)
	b.bytes += n
	if err != nil {
		return "", err
	}
	if uint64(n) != entry.UncompressedSize64 {
		return "", fmt.Errorf("nested JAR size mismatch")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func mavenGroups(ctx context.Context, entries []*zip.File, prefix string, b *budget) ([]string, error) {
	if len(entries) > MaxEntries {
		return nil, fmt.Errorf("JAR entry limit exceeded")
	}
	var groups []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name, prefix+"META-INF/maven/") && strings.HasSuffix(entry.Name, "/pom.properties") {
			if entry.UncompressedSize64 > 64<<10 {
				return nil, fmt.Errorf("Maven metadata exceeds limit")
			}
			source, err := entry.Open()
			if err != nil {
				return nil, err
			}
			var body strings.Builder
			limit := int64(64 << 10)
			if MaxExpandedBytes-b.bytes < limit {
				limit = MaxExpandedBytes - b.bytes
			}
			n, err := boundedCopy(ctx, &body, source, limit)
			_ = source.Close()
			b.bytes += n
			if err != nil {
				return nil, err
			}
			for _, line := range strings.Split(body.String(), "\n") {
				key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
				if ok && strings.TrimSpace(key) == "groupId" {
					value = strings.TrimSpace(value)
					if value != "" && len(value) <= 256 {
						groups = append(groups, value)
					}
				}
			}
		}
	}
	return unique(groups), nil
}

func boundedCopy(ctx context.Context, target io.Writer, source io.Reader, limit int64) (int64, error) {
	var total int64
	buffer := make([]byte, 64<<10)
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		n, err := source.Read(buffer)
		if int64(n) > limit-total {
			return total, fmt.Errorf("cumulative JAR expansion limit exceeded")
		}
		if n > 0 {
			written, writeErr := target.Write(buffer[:n])
			total += int64(written)
			if writeErr != nil {
				return total, writeErr
			}
			if written != n {
				return total, io.ErrShortWrite
			}
		}
		if err == io.EOF {
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
}

func fileDigest(filename string) string {
	file, err := os.Open(filename)
	if err != nil {
		return ""
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return ""
	}
	return hex.EncodeToString(hash.Sum(nil))
}
func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
func unique(values []string) []string {
	result := []string{}
	for _, value := range values {
		if !contains(result, value) {
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}
func safeEntry(name string) bool {
	name = strings.TrimSuffix(name, "/")
	if name == "" || strings.HasPrefix(name, "/") || strings.ContainsAny(name, "\\:\x00\r\n\t") || path.Clean(name) != name {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

// Bundle writes only normalized class JARs; manifests/resources and arbitrary
// nested files never reach the bytecode analyzer. Transport is bounded on disk.
func (p *Prepared) Bundle(ctx context.Context, filename string) error {
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	writer := zip.NewWriter(file)
	var targets, all int64
	for _, group := range []struct {
		prefix string
		units  []Unit
	}{{"targets", p.Targets}, {"deps", p.Dependencies}} {
		for index, unit := range group.units {
			info, err := os.Stat(unit.Path)
			if err != nil {
				return err
			}
			all += info.Size()
			if group.prefix == "targets" {
				targets += info.Size()
			}
			if all > MaxBundleBytes || targets > MaxTargetBytes {
				return fmt.Errorf("prepared bytecode targets or dependencies exceed bundle limits")
			}
			header := &zip.FileHeader{Name: fmt.Sprintf("%s/%04d.jar", group.prefix, index), Method: zip.Store}
			destination, err := writer.CreateHeader(header)
			if err != nil {
				return err
			}
			source, err := os.Open(unit.Path)
			if err != nil {
				return err
			}
			_, copyErr := boundedCopy(ctx, destination, source, info.Size())
			_ = source.Close()
			if copyErr != nil {
				return copyErr
			}
		}
	}
	if err := writer.Close(); err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Size() > MaxBundleBytes {
		return fmt.Errorf("prepared bytecode bundle exceeds transport limit")
	}
	return file.Close()
}
