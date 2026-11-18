package jvmarchive

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"

	"binaryscan.local/backend/internal/sbom"
)

// Inventory preserves all release variants. Effective bytecode selection belongs
// to a particular environment's impact analysis, never the shared inventory.
func Inventory(ctx context.Context, filename, logicalPath string) (sbom.Document, error) {
	var d sbom.Document
	info, e := os.Stat(filename)
	if e != nil {
		return d, e
	}
	if info.Size() > MaxInputBytes {
		return d, fmt.Errorf("JAVA_ARCHIVE_INPUT_LIMIT")
	}
	data, e := os.ReadFile(filename)
	if e != nil {
		return d, e
	}
	d = sbom.Document{Standard: "JavaArchive", SpecVersion: "1", Encoding: "zip", InputSHA256: sbom.BytesDigest(data), DocumentID: logicalPath}
	var expanded int64
	entries := 0
	modules := 0
	var walk func([]byte, string, int) error
	walk = func(data []byte, location string, depth int) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if depth > 4 {
			return fmt.Errorf("JAVA_ARCHIVE_DEPTH_LIMIT")
		}
		modules++
		if modules > MaxModules {
			return fmt.Errorf("JAVA_MODULE_LIMIT")
		}
		z, e := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if e != nil {
			return e
		}
		seen := map[string]bool{}
		coordinates := []map[string]string{}
		nested := []*zip.File{}
		classes := 0
		for _, f := range z.File {
			entries++
			if entries > MaxEntries {
				return fmt.Errorf("JAVA_ENTRY_LIMIT")
			}
			if !safeEntry(f.Name) || seen[f.Name] || f.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("JAVA_UNSAFE_OR_DUPLICATE_ENTRY: %s", f.Name)
			}
			seen[f.Name] = true
			if f.UncompressedSize64 > uint64(MaxExpandedBytes) || int64(f.UncompressedSize64) > MaxExpandedBytes-expanded {
				return fmt.Errorf("JAVA_EXPANSION_LIMIT")
			}
			expanded += int64(f.UncompressedSize64)
			if strings.HasSuffix(f.Name, ".class") {
				classes++
			}
			if strings.HasSuffix(strings.ToLower(f.Name), ".jar") {
				nested = append(nested, f)
			}
			if strings.HasSuffix(f.Name, "/pom.properties") && strings.Contains(f.Name, "META-INF/maven/") {
				b, e := readInventoryEntry(f, 1<<20)
				if e != nil {
					return e
				}
				m := map[string]string{}
				for _, line := range strings.Split(string(b), "\n") {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, "#") {
						continue
					}
					k, v, ok := strings.Cut(line, "=")
					if ok {
						m[strings.TrimSpace(k)] = strings.TrimSpace(v)
					}
				}
				if m["groupId"] != "" && m["artifactId"] != "" && m["version"] != "" {
					coordinates = append(coordinates, m)
				}
			}
			if f.Name == "META-INF/MANIFEST.MF" {
				b, e := readInventoryEntry(f, 1<<20)
				if e != nil {
					return e
				}
				if strings.Contains(string(b), "Class-Path:") {
					d.Diagnostics = append(d.Diagnostics, sbom.Diagnostic{Code: "EXTERNAL_CLASSPATH_UNVERIFIED", Message: "Manifest class path is not followed; external dependencies require an explicit environment", Ref: location})
				}
			}
		}
		c := sbom.Component{SourceRef: location, Path: location, Name: path.Base(location), SHA256: sbom.BytesDigest(data)}
		if len(coordinates) == 1 {
			m := coordinates[0]
			c.Name = m["artifactId"]
			c.Group = m["groupId"]
			c.Version = m["version"]
			c.PURL = sbom.MavenPURL(c.Group, c.Name, c.Version)
		} else if len(coordinates) > 1 {
			d.Diagnostics = append(d.Diagnostics, sbom.Diagnostic{Code: "AMBIGUOUS_SHADED_IDENTITY", Message: "Multiple Maven coordinates in one archive; exact component identity is not inferred", Ref: location})
		}
		if classes > 0 || len(nested) == 0 {
			d.Components = append(d.Components, c)
		}
		sort.Slice(nested, func(i, j int) bool { return nested[i].Name < nested[j].Name })
		for _, f := range nested {
			b, e := readInventoryEntry(f, MaxInputBytes)
			if e != nil {
				return e
			}
			child := location + "!/" + f.Name
			if e = walk(b, child, depth+1); e != nil {
				return e
			}
			if classes > 0 {
				d.Dependencies = append(d.Dependencies, sbom.Dependency{From: location, To: child, Type: "CONTAINS"})
			}
		}
		return nil
	}
	if e = walk(data, logicalPath, 0); e != nil {
		return d, e
	}
	e = sbom.Finalize(&d)
	return d, e
}
func readInventoryEntry(f *zip.File, limit int64) ([]byte, error) {
	if f.UncompressedSize64 > uint64(limit) {
		return nil, fmt.Errorf("JAVA_ENTRY_SIZE_LIMIT")
	}
	r, e := f.Open()
	if e != nil {
		return nil, e
	}
	defer r.Close()
	b, e := io.ReadAll(io.LimitReader(r, limit+1))
	if e != nil {
		return nil, e
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("JAVA_ENTRY_SIZE_LIMIT")
	}
	return b, nil
}
