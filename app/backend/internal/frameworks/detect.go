// Package frameworks records bounded, original-binary framework evidence. It
// does not infer dependencies from filenames or decide whether a finding is safe.
package frameworks

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
)

const Version = "framework-evidence-v1"
const (
	MaxInputBytes    int64 = 256 << 20
	maxNestedBytes   int64 = 64 << 20
	maxExpandedBytes int64 = 256 << 20
	maxMetadataBytes int64 = 64 << 10
	maxManifestBytes int64 = 1 << 20
	maxEntries             = 100_000
)

var ErrLimit = errors.New("framework evidence exceeds bounded archive limits")
var coordinatePart = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,199}$`)
var versionValue = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.+\-]{0,127}$`)

type Evidence struct {
	Coordinate string `json:"coordinate"`
	Version    string `json:"version"`
	EntryPath  string `json:"entryPath"`
	Source     string `json:"source"`
	JARSHA256  string `json:"jarSha256"`
}

type Conflict struct {
	Coordinate string   `json:"coordinate"`
	Versions   []string `json:"versions"`
	Entries    []string `json:"entries"`
}

type Snapshot struct {
	Version     string            `json:"version"`
	InputSHA256 string            `json:"inputSha256"`
	Artifacts   map[string]string `json:"artifacts"`
	Conflicts   []Conflict        `json:"conflicts"`
	Evidence    []Evidence        `json:"evidence"`
	Diagnostics []string          `json:"diagnostics"`
	// Digest is SHA-256 of ONLY the key-sorted compact UTF-8 JSON artifacts map.
	// Original bytes are separately bound by InputSHA256. Conflicts are excluded
	// from Artifacts, while every claimed version and source remains auditable.
	Digest string `json:"digest"`
}

func Empty(inputSHA256 string) Snapshot {
	s := Snapshot{Version: Version, InputSHA256: strings.ToLower(inputSHA256), Artifacts: map[string]string{}, Conflicts: []Conflict{}, Evidence: []Evidence{}, Diagnostics: []string{}}
	s.Digest = ArtifactsDigest(s.Artifacts)
	return s
}

// ArtifactsDigest matches Java's TreeMap<String,String> compact JSON encoding.
// Detected keys and versions are restricted to ASCII characters requiring no
// escaping. Go's JSON encoder orders map keys lexicographically.
func ArtifactsDigest(artifacts map[string]string) string {
	if artifacts == nil {
		artifacts = map[string]string{}
	}
	body, _ := json.Marshal(artifacts)
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}

// Detect verifies the exact original file, then reads only bounded Maven and
// strict manifest/class evidence. A JVM class returns an explicit empty map.
func Detect(ctx context.Context, filename string, expectedSize int64, expectedSHA256 []byte) (Snapshot, error) {
	if expectedSize < 4 || expectedSize > MaxInputBytes {
		return Snapshot{}, fmt.Errorf("%w: original input size", ErrLimit)
	}
	if len(expectedSHA256) != sha256.Size {
		return Snapshot{}, errors.New("framework evidence requires a SHA-256 input identity")
	}
	info, err := os.Lstat(filename)
	if err != nil {
		return Snapshot{}, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() != expectedSize {
		return Snapshot{}, errors.New("framework evidence input is not the expected regular file")
	}
	file, err := os.Open(filename)
	if err != nil {
		return Snapshot{}, err
	}
	defer file.Close()
	if err := verify(ctx, file, expectedSize, expectedSHA256); err != nil {
		return Snapshot{}, err
	}
	inputSHA := hex.EncodeToString(expectedSHA256)
	snapshot := Empty(inputSHA)
	var magic [4]byte
	if _, err := file.ReadAt(magic[:], 0); err != nil {
		return Snapshot{}, err
	}
	if bytes.Equal(magic[:], []byte{0xca, 0xfe, 0xba, 0xbe}) {
		return snapshot, nil
	}
	archive, err := zip.NewReader(file, expectedSize)
	if err != nil {
		return Snapshot{}, fmt.Errorf("framework evidence requires a JVM class or JAR: %w", err)
	}
	androidManifest, dex := false, false
	for _, entry := range archive.File {
		androidManifest = androidManifest || entry.Name == "AndroidManifest.xml"
		dex = dex || (strings.HasPrefix(entry.Name, "classes") && strings.HasSuffix(entry.Name, ".dex") && !strings.Contains(entry.Name, "/"))
	}
	if androidManifest && dex {
		return Snapshot{}, errors.New("APK is outside JVM framework evidence scope")
	}
	scanner := archiveScanner{ctx: ctx, remaining: maxExpandedBytes, snapshot: &snapshot}
	if err := scanner.scan(archive, "", inputSHA, true); err != nil {
		return Snapshot{}, err
	}
	// Recheck immutable input identity after reading central directories and
	// nested metadata; reuse the same open file rather than reopening a path.
	if err := verify(ctx, file, expectedSize, expectedSHA256); err != nil {
		return Snapshot{}, err
	}
	finalize(&snapshot)
	return snapshot, nil
}

func verify(ctx context.Context, file *os.File, size int64, expected []byte) error {
	stat, err := file.Stat()
	if err != nil {
		return err
	}
	if !stat.Mode().IsRegular() || stat.Size() != size {
		return errors.New("framework evidence input size changed")
	}
	hash := sha256.New()
	read, err := io.Copy(hash, contextReader{ctx, io.NewSectionReader(file, 0, size+1)})
	if err != nil {
		return err
	}
	if read != size || !bytes.Equal(hash.Sum(nil), expected) {
		return errors.New("framework evidence input digest does not match original blob")
	}
	return nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

type archiveScanner struct {
	ctx       context.Context
	remaining int64
	entries   int
	snapshot  *Snapshot
}

func (s *archiveScanner) scan(archive *zip.Reader, prefix, jarSHA string, nested bool) error {
	if err := s.ctx.Err(); err != nil {
		return err
	}
	s.entries += len(archive.File)
	if s.entries > maxEntries {
		return fmt.Errorf("%w: archive entries", ErrLimit)
	}
	entries := make(map[string]*zip.File, len(archive.File))
	for _, entry := range archive.File {
		if !safeEntry(entry.Name) {
			return fmt.Errorf("unsafe framework archive entry %q", entry.Name)
		}
		if _, duplicate := entries[entry.Name]; duplicate {
			return fmt.Errorf("duplicate framework archive entry %q", entry.Name)
		}
		entries[entry.Name] = entry
	}
	for _, entry := range archive.File {
		if err := s.ctx.Err(); err != nil {
			return err
		}
		if strings.HasPrefix(entry.Name, "META-INF/maven/") && strings.HasSuffix(entry.Name, "/pom.properties") {
			body, err := s.read(entry, maxMetadataBytes)
			if err != nil {
				return err
			}
			s.maven(body, prefix+entry.Name, jarSHA)
		}
	}
	if manifest := entries["META-INF/MANIFEST.MF"]; manifest != nil {
		body, err := s.read(manifest, maxManifestBytes)
		if err != nil {
			return err
		}
		if err := s.manifest(body, entries, prefix, jarSHA); err != nil {
			return err
		}
	}
	if nested {
		for _, entry := range archive.File {
			if !strings.HasPrefix(entry.Name, "BOOT-INF/lib/") || !strings.HasSuffix(entry.Name, ".jar") || strings.Contains(strings.TrimPrefix(entry.Name, "BOOT-INF/lib/"), "/") {
				continue
			}
			body, err := s.read(entry, maxNestedBytes)
			if err != nil {
				return err
			}
			child, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
			if err != nil {
				return fmt.Errorf("invalid nested framework JAR %s: %w", entry.Name, err)
			}
			digest := sha256.Sum256(body)
			if err := s.scan(child, prefix+entry.Name+"!/", hex.EncodeToString(digest[:]), false); err != nil {
				return err
			}
		}
	}
	return nil
}

func safeEntry(name string) bool {
	if name == "" || strings.HasPrefix(name, "/") || strings.ContainsAny(name, "\\:\x00") {
		return false
	}
	trimmed := strings.TrimSuffix(name, "/")
	return trimmed != "" && path.Clean(trimmed) == trimmed && trimmed != ".." && !strings.HasPrefix(trimmed, "../")
}

func (s *archiveScanner) read(entry *zip.File, limit int64) ([]byte, error) {
	if entry.UncompressedSize64 > uint64(limit) || entry.UncompressedSize64 > uint64(s.remaining) {
		return nil, fmt.Errorf("%w: %s", ErrLimit, entry.Name)
	}
	reader, err := entry.Open()
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	body, err := io.ReadAll(io.LimitReader(contextReader{s.ctx, reader}, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit || int64(len(body)) > s.remaining {
		return nil, ErrLimit
	}
	s.remaining -= int64(len(body))
	return body, nil
}

func (s *archiveScanner) maven(body []byte, entry, jarSHA string) {
	properties, err := parseProperties(body)
	if err != nil {
		s.diagnostic("unreadable Maven properties at " + entry)
		return
	}
	groups, artifacts := unique(properties["groupId"]), unique(properties["artifactId"])
	if len(groups) != 1 || len(artifacts) != 1 {
		s.diagnostic("ambiguous or missing Maven coordinate at " + entry)
		return
	}
	group, artifact := groups[0], artifacts[0]
	coordinate := group + ":" + artifact
	if !supported[coordinate] {
		return
	}
	if !coordinatePart.MatchString(group) || !coordinatePart.MatchString(artifact) {
		s.diagnostic("invalid Maven coordinate at " + entry)
		return
	}
	versions := unique(properties["version"])
	if len(versions) == 0 {
		s.diagnostic("missing Maven version for " + coordinate + " at " + entry)
	}
	for _, version := range versions {
		if !versionValue.MatchString(version) {
			s.diagnostic("unresolved Maven version for " + coordinate + " at " + entry)
			continue
		}
		s.snapshot.Evidence = append(s.snapshot.Evidence, Evidence{coordinate, version, entry, "pom.properties", jarSHA})
	}
}

func (s *archiveScanner) diagnostic(message string) {
	if len(s.snapshot.Diagnostics) < 1000 {
		s.snapshot.Diagnostics = append(s.snapshot.Diagnostics, message)
	}
}

func finalize(snapshot *Snapshot) {
	sort.Slice(snapshot.Evidence, func(i, j int) bool {
		a, b := snapshot.Evidence[i], snapshot.Evidence[j]
		if a.Coordinate != b.Coordinate {
			return a.Coordinate < b.Coordinate
		}
		if a.Version != b.Version {
			return a.Version < b.Version
		}
		if a.EntryPath != b.EntryPath {
			return a.EntryPath < b.EntryPath
		}
		return a.Source < b.Source
	})
	versions := map[string][]string{}
	entries := map[string][]string{}
	for _, evidence := range snapshot.Evidence {
		versions[evidence.Coordinate] = append(versions[evidence.Coordinate], evidence.Version)
		entries[evidence.Coordinate] = append(entries[evidence.Coordinate], evidence.EntryPath)
	}
	coordinates := make([]string, 0, len(versions))
	for coordinate := range versions {
		coordinates = append(coordinates, coordinate)
	}
	sort.Strings(coordinates)
	for _, coordinate := range coordinates {
		values := unique(versions[coordinate])
		if len(values) == 1 {
			snapshot.Artifacts[coordinate] = values[0]
		} else {
			snapshot.Conflicts = append(snapshot.Conflicts, Conflict{coordinate, values, unique(entries[coordinate])})
		}
	}
	sort.Strings(snapshot.Diagnostics)
	snapshot.Digest = ArtifactsDigest(snapshot.Artifacts)
}

func unique(values []string) []string {
	seen := map[string]bool{}
	for _, value := range values {
		seen[value] = true
	}
	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
