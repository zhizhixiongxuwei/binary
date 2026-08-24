package filetype

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"binaryscan.local/backend/internal/containerarchive"
)

type Category string

const (
	CategoryBinary    Category = "binary"
	CategoryArchive   Category = "archive"
	CategoryContainer Category = "container"
)

type Result struct {
	Category Category
	Format   string
}

// ErrInvalidInput marks parser failures caused by malformed or deliberately
// over-complex user input. Callers may safely persist these as unsupported
// uploads. Filesystem and other operational errors are intentionally not
// wrapped with this sentinel so callers can return a retryable server error.
var ErrInvalidInput = errors.New("invalid binary input")

func ParseCategory(value string) (Category, bool) {
	switch Category(strings.ToLower(strings.TrimSpace(value))) {
	case CategoryBinary:
		return CategoryBinary, true
	case CategoryArchive:
		return CategoryArchive, true
	case CategoryContainer:
		return CategoryContainer, true
	default:
		return "", false
	}
}

func CategoryForFormat(format string) (Category, bool) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "pe32", "pe32+", "elf32", "elf64", "macho-thin", "macho-fat", "java-class", "jar", "dex", "apk", "pyc",
		"pe", "elf", "mach-o", "macho", "class", "war", "ear":
		return CategoryBinary, true
	case "zip", "7z", "rar", "tar", "gzip", "xz", "deb", "rpm":
		return CategoryArchive, true
	case "iso9660":
		return CategoryArchive, true
	case containerarchive.FormatDockerTAR, containerarchive.FormatOCITAR:
		return CategoryContainer, true
	default:
		return "", false
	}
}

// Detect returns the canonical server-side category and format. Extensions are
// used only where the container format itself is ambiguous (ZIP and PYC).
func Detect(filename, logicalPath string) (Result, error) {
	file, err := os.Open(filename)
	if err != nil {
		return Result{}, fmt.Errorf("open file for detection: %w", err)
	}
	defer file.Close()
	// ISO 9660 volume descriptors start at sector 16 (32 KiB). Keep the read
	// bounded while including enough data for content-based ISO detection.
	header := make([]byte, 40*1024)
	count, err := io.ReadFull(file, header)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return Result{}, fmt.Errorf("read file header: %w", err)
	}
	header = header[:count]
	extension := strings.ToLower(filepath.Ext(logicalPath))

	if peFormat, ok := detectPE(file, header); ok {
		return result(peFormat), nil
	}
	if len(header) >= 4 && bytes.Equal(header[:4], []byte{0x7f, 'E', 'L', 'F'}) {
		if len(header) > 4 && header[4] == 1 {
			return result("elf32"), nil
		}
		return result("elf64"), nil
	}
	if isDEX(header) {
		return result("dex"), nil
	}
	if isJavaClass(header) {
		return result("java-class"), nil
	}
	if machOFormat, ok := detectMachO(header); ok {
		return result(machOFormat), nil
	}
	if isZIP(header) {
		format, inspectErr := inspectZIP(filename, extension)
		if inspectErr != nil {
			return Result{}, classifyInspectionError(inspectErr)
		}
		return result(format), nil
	}
	if isPYC(header, extension) {
		return result("pyc"), nil
	}
	if len(header) >= 6 && bytes.Equal(header[:6], []byte{0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c}) {
		return result("7z"), nil
	}
	if len(header) >= 8 && (bytes.Equal(header[:7], []byte("Rar!\x1a\x07\x00")) || bytes.Equal(header[:8], []byte("Rar!\x1a\x07\x01\x00"))) {
		return result("rar"), nil
	}
	if len(header) >= 2 && bytes.Equal(header[:2], []byte{0x1f, 0x8b}) {
		return result("gzip"), nil
	}
	if len(header) >= 6 && bytes.Equal(header[:6], []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}) {
		return result("xz"), nil
	}
	if len(header) >= 4 && bytes.Equal(header[:4], []byte{0xed, 0xab, 0xee, 0xdb}) {
		return result("rpm"), nil
	}
	if isISO9660(header) {
		return result("iso9660"), nil
	}
	if isDebianPackage(file, header) {
		return result("deb"), nil
	}
	if isTAR(filename) {
		format, ok, inspectErr := containerarchive.InspectTAR(filename)
		if inspectErr != nil {
			return Result{}, classifyInspectionError(inspectErr)
		}
		if ok {
			return result(format), nil
		}
		return result("tar"), nil
	}
	return Result{Format: "unknown"}, nil
}

func classifyInspectionError(err error) error {
	var pathError *os.PathError
	if errors.As(err, &pathError) {
		return err
	}
	return fmt.Errorf("%w: %v", ErrInvalidInput, err)
}

func result(format string) Result {
	category, _ := CategoryForFormat(format)
	return Result{Category: category, Format: format}
}

func detectPE(file *os.File, header []byte) (string, bool) {
	if len(header) < 64 || !bytes.Equal(header[:2], []byte{'M', 'Z'}) {
		return "", false
	}
	offset := int64(binary.LittleEndian.Uint32(header[0x3c:0x40]))
	if offset < 64 || offset > 16<<20 {
		return "", false
	}
	var peHeader [26]byte
	count, err := file.ReadAt(peHeader[:], offset)
	if err != nil && !errors.Is(err, io.EOF) || count < 4 || !bytes.Equal(peHeader[:4], []byte{'P', 'E', 0, 0}) {
		return "", false
	}
	if count >= len(peHeader) && binary.LittleEndian.Uint16(peHeader[24:26]) == 0x20b {
		return "pe32+", true
	}
	return "pe32", true
}

func isDEX(header []byte) bool {
	return len(header) >= 8 && bytes.Equal(header[:4], []byte("dex\n")) &&
		header[4] >= '0' && header[4] <= '9' && header[5] >= '0' && header[5] <= '9' &&
		header[6] >= '0' && header[6] <= '9' && header[7] == 0
}

func isJavaClass(header []byte) bool {
	if len(header) < 8 || !bytes.Equal(header[:4], []byte{0xca, 0xfe, 0xba, 0xbe}) {
		return false
	}
	major := binary.BigEndian.Uint16(header[6:8])
	return major >= 45 && major <= 100
}

func isPYC(header []byte, extension string) bool {
	return extension == ".pyc" && len(header) >= 16 && header[2] == '\r' && header[3] == '\n'
}

func isZIP(header []byte) bool {
	return len(header) >= 4 && (bytes.Equal(header[:4], []byte{'P', 'K', 3, 4}) ||
		bytes.Equal(header[:4], []byte{'P', 'K', 5, 6}) || bytes.Equal(header[:4], []byte{'P', 'K', 7, 8}))
}

func isISO9660(header []byte) bool {
	const sectorSize = 2048
	for sector := 16; sector <= 18; sector++ {
		offset := sector * sectorSize
		if len(header) < offset+7 {
			return false
		}
		descriptorType := header[offset]
		if bytes.Equal(header[offset+1:offset+6], []byte("CD001")) && header[offset+6] == 1 {
			if descriptorType == 1 || descriptorType == 2 {
				return true
			}
			if descriptorType == 255 {
				return false
			}
		}
	}
	return false
}

func inspectZIP(filename, extension string) (string, error) {
	reader, err := zip.OpenReader(filename)
	if err != nil {
		return "", fmt.Errorf("inspect ZIP input: %w", err)
	}
	defer reader.Close()
	if len(reader.File) > 20000 {
		return "", fmt.Errorf("ZIP entry limit exceeded during detection")
	}
	var manifest, classFile, androidManifest, dexFile bool
	for _, file := range reader.File {
		name := strings.TrimPrefix(strings.ReplaceAll(file.Name, "\\", "/"), "./")
		switch {
		case strings.EqualFold(name, "META-INF/MANIFEST.MF"):
			manifest = true
		case strings.HasSuffix(strings.ToLower(name), ".class"):
			classFile = true
		case name == "AndroidManifest.xml":
			androidManifest = true
		case name == "classes.dex" || (strings.HasPrefix(name, "classes") && strings.HasSuffix(name, ".dex")):
			dexFile = true
		}
	}
	if androidManifest && dexFile {
		return "apk", nil
	}
	if manifest || (extension == ".jar" && classFile) {
		return "jar", nil
	}
	// A generic ZIP may legitimately contain CLASS candidates. That is the
	// archive-import use case and must not be promoted to a JAR solely because
	// a member happens to end in .class.
	return "zip", nil
}

func isDebianPackage(file *os.File, header []byte) bool {
	if len(header) < 68 || !bytes.Equal(header[:8], []byte("!<arch>\n")) {
		return false
	}
	var memberHeader [60]byte
	if _, err := file.ReadAt(memberHeader[:], 8); err != nil {
		return false
	}
	name := strings.TrimSuffix(strings.TrimSpace(string(memberHeader[:16])), "/")
	if name != "debian-binary" || string(memberHeader[58:60]) != "`\n" {
		return false
	}
	size, err := strconv.ParseInt(strings.TrimSpace(string(memberHeader[48:58])), 10, 64)
	return err == nil && size > 0 && size < 1024
}

func isTAR(filename string) bool {
	file, err := os.Open(filename)
	if err != nil {
		return false
	}
	defer file.Close()
	_, err = tar.NewReader(file).Next()
	return err == nil
}

func detectMachO(header []byte) (string, bool) {
	if len(header) < 4 {
		return "", false
	}
	magic := header[:4]
	thin := [][]byte{
		{0xfe, 0xed, 0xfa, 0xce}, {0xce, 0xfa, 0xed, 0xfe},
		{0xfe, 0xed, 0xfa, 0xcf}, {0xcf, 0xfa, 0xed, 0xfe},
	}
	for _, value := range thin {
		if bytes.Equal(magic, value) {
			return "macho-thin", true
		}
	}
	if bytes.Equal(magic, []byte{0xca, 0xfe, 0xba, 0xbe}) || bytes.Equal(magic, []byte{0xbe, 0xba, 0xfe, 0xca}) {
		return "macho-fat", true
	}
	return "", false
}
