package storage

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	JVMSourceMapPath   = "jvm-source-map.tsv"
	jvmSourceMapHeader = "binaryscan-vineflower-map-v1"
	jvmSourceMapLimit  = 16 << 20
	jvmSourceMapRows   = 200000
)

type ManifestSidecar struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"sizeBytes"`
}

// JVMSourceLocation relates an original dereference instruction to the generated file.
type JVMSourceLocation struct {
	Path, ClassName, MethodName, MethodDescriptor string
	DereferenceKind, MemberName                   string
	BytecodeOffset, Line                          int
}

func (w *Workspace) WriteJVMSourceMap(source io.Reader) error {
	body, err := io.ReadAll(io.LimitReader(source, jvmSourceMapLimit+1))
	if err != nil {
		return err
	}
	locations, err := parseJVMSourceMap(body, w.files)
	if err != nil || len(locations) == 0 {
		return err
	}
	path := filepath.Join(w.root, JVMSourceMapPath)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(body)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		_ = os.Remove(path)
		return fmt.Errorf("write JVM source map: write=%v close=%v", writeErr, closeErr)
	}
	w.jvmSourceMap = &ManifestSidecar{Path: JVMSourceMapPath, SHA256: fmt.Sprintf("%x", sha256.Sum256(body)), SizeBytes: int64(len(body))}
	return nil
}

// ReadJVMSourceMap accepts only the map bound by the already verified project manifest.
func ReadJVMSourceMap(projectRoot string, manifest Manifest) ([]JVMSourceLocation, error) {
	sidecar := manifest.JVMSourceMap
	if sidecar == nil {
		return nil, nil
	}
	if manifest.Kind != "jvm" || manifest.ToolName != "vineflower" || sidecar.Path != JVMSourceMapPath ||
		sidecar.SizeBytes <= 0 || sidecar.SizeBytes > jvmSourceMapLimit {
		return nil, fmt.Errorf("invalid JVM source map metadata")
	}
	path := filepath.Join(projectRoot, JVMSourceMapPath)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() != sidecar.SizeBytes {
		return nil, fmt.Errorf("JVM source map does not match project metadata")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, sidecar.SizeBytes+1))
	if err != nil || int64(len(body)) != sidecar.SizeBytes ||
		fmt.Sprintf("%x", sha256.Sum256(body)) != sidecar.SHA256 {
		return nil, fmt.Errorf("JVM source map does not match project digest")
	}
	files := make(map[string]ManifestFile, len(manifest.Files))
	for _, file := range manifest.Files {
		files[file.Path] = file
	}
	return parseJVMSourceMap(body, files)
}

func parseJVMSourceMap(body []byte, files map[string]ManifestFile) ([]JVMSourceLocation, error) {
	if len(body) > jvmSourceMapLimit || !utf8.Valid(body) {
		return nil, fmt.Errorf("JVM source map exceeds size limit or contains invalid UTF-8")
	}
	rows := bufio.NewScanner(bytes.NewReader(body))
	rows.Buffer(make([]byte, 4096), 16<<10)
	if !rows.Scan() || rows.Text() != jvmSourceMapHeader {
		return nil, fmt.Errorf("invalid JVM source map header")
	}
	var locations []JVMSourceLocation
	type instruction struct {
		class, method, descriptor string
		offset                    int
	}
	seen := make(map[instruction]struct{})
	for rows.Scan() {
		if len(locations) >= jvmSourceMapRows {
			return nil, fmt.Errorf("JVM source map exceeds row limit")
		}
		fields := strings.Split(rows.Text(), "\t")
		if len(fields) != 8 {
			return nil, fmt.Errorf("invalid JVM source map row")
		}
		path, className, method, descriptor := fields[0], fields[1], fields[2], fields[3]
		offset, offsetErr := strconv.Atoi(fields[4])
		line, lineErr := strconv.Atoi(fields[5])
		kind, member := fields[6], fields[7]
		file, known := files[path]
		cleaned, pathErr := CleanRelativePath(path)
		classPath, classErr := CleanRelativePath(className)
		if pathErr != nil || cleaned != path || !validMapIdentity(path) || !known || file.Language != "java" ||
			classErr != nil || classPath != className || strings.ContainsAny(className, ".;[") ||
			!validMapIdentity(className) || !validMapIdentity(method) || !validMapIdentity(descriptor) ||
			!strings.HasPrefix(descriptor, "(") || !strings.Contains(descriptor, ")") ||
			offsetErr != nil || offset < 0 || offset >= 65535 || lineErr != nil || line < 1 || line > file.LineCount ||
			!validDereference(kind, member) {
			return nil, fmt.Errorf("invalid JVM source map location")
		}
		key := instruction{className, method, descriptor, offset}
		if _, exists := seen[key]; exists {
			return nil, fmt.Errorf("ambiguous JVM source map instruction")
		}
		seen[key] = struct{}{}
		locations = append(locations, JVMSourceLocation{
			Path: path, ClassName: className, MethodName: method, MethodDescriptor: descriptor,
			BytecodeOffset: offset, Line: line, DereferenceKind: kind, MemberName: member,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read JVM source map row: %w", err)
	}
	return locations, nil
}

func validMapIdentity(value string) bool {
	return value != "" && strings.IndexFunc(value, unicode.IsControl) < 0
}

func validDereference(kind, member string) bool {
	switch kind {
	case "instance-method", "instance-field":
		return validMapIdentity(member)
	case "array-access", "array-length", "monitor":
		return member == ""
	default:
		return false
	}
}
