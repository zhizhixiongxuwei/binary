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

type AnalysisMode string

const (
	// Category 是服务端依据文件内容给出的推荐类别；AnalysisMode 是用户最终选择的处理流程。
	// 两者故意分开，因此 TAR/ISO/EXT4 等多义载体可以保留真实识别结果，同时按用户选择尝试归档或映像流程。
	CategoryBinary    Category = "binary"
	CategoryArchive   Category = "archive"
	CategoryContainer Category = "container"

	AnalysisModeBinary    AnalysisMode = "binary"
	AnalysisModeArchive   AnalysisMode = "archive"
	AnalysisModeContainer AnalysisMode = "container"
)

type Result struct {
	Category Category
	Format   string
}

// ErrInvalidInput 标记畸形或刻意构造得过于复杂的用户输入。调用方可把它持久化为“不支持”；
// 文件系统等运行错误不包装该哨兵，从而仍能按可重试的服务端故障处理。
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

func ParseAnalysisMode(value string) (AnalysisMode, bool) {
	switch AnalysisMode(strings.ToLower(strings.TrimSpace(value))) {
	case AnalysisModeBinary:
		return AnalysisModeBinary, true
	case AnalysisModeArchive:
		return AnalysisModeArchive, true
	case AnalysisModeContainer:
		return AnalysisModeContainer, true
	default:
		return "", false
	}
}

// SupportsAnalysisMode 判断当前引擎是否能执行用户选择的流程。即使返回 false，上层仍可创建任务并
// 明确记录“不适用”，从审计语义上区分“不支持该模式”和“检测成功但零命中”。
func SupportsAnalysisMode(format string, mode AnalysisMode) bool {
	format = strings.ToLower(strings.TrimSpace(format))
	switch mode {
	case AnalysisModeBinary:
		switch format {
		case "pe32", "pe32+", "elf32", "elf64", "macho-thin", "macho-fat", "java-class",
			"jar", "war", "ear", "dex", "apk", "pyc", "pe", "elf", "mach-o", "macho", "class":
			return true
		}
	case AnalysisModeArchive:
		_, ok := ArchiveFormat(format)
		return ok
	case AnalysisModeContainer:
		return format == containerarchive.FormatDockerTAR || format == containerarchive.FormatOCITAR
	}
	return false
}

// ArchiveFormat 把 JAR/APK 等 ZIP 容器以及 Docker/OCI TAR 归一化到实际兼容的一层归档读取器；
// 这里只决定读取方式，不等同于把文件业务类别永久改成“归档”。
func ArchiveFormat(format string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "zip", "7z", "rar", "tar", "gzip", "xz", "deb", "rpm", "iso9660", "ext4":
		return strings.ToLower(strings.TrimSpace(format)), true
	case "jar", "war", "ear", "apk":
		return "zip", true
	case containerarchive.FormatDockerTAR, containerarchive.FormatOCITAR:
		return "tar", true
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
	case "ext4":
		return CategoryContainer, true
	case containerarchive.FormatDockerTAR, containerarchive.FormatOCITAR:
		return CategoryContainer, true
	default:
		return "", false
	}
}

// Detect 通过受限头部读取和必要的结构检查返回规范格式。扩展名只在 PYC、ZIP 应用包等
// 内容自身不足以消除歧义的场景作为辅助；IMG 后缀不会覆盖内部 Docker/OCI/TAR/EXT4 证据。
func Detect(filename, logicalPath string) (Result, error) {
	file, err := os.Open(filename)
	if err != nil {
		return Result{}, fmt.Errorf("open file for detection: %w", err)
	}
	defer file.Close()
	// ISO 9660 卷描述符从第 16 扇区（32 KiB）开始；固定读取 40 KiB，既覆盖识别区域又限制内存。
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
	// EXT 超级块从 1024 字节开始，s_magic 位于块内 0x38。把该检查放在 TAR 之后，确保改名为
	// .img 的 Docker/OCI archive 优先按真实容器结构识别。当前没有 rootfs 物化器，原始 EXT4
	// 只能只读枚举归档成员，Trivy 明确判定为不适用。
	const extMagicOffset = 1024 + 0x38
	if len(header) >= extMagicOffset+2 && binary.LittleEndian.Uint16(header[extMagicOffset:extMagicOffset+2]) == 0xef53 {
		return result("ext4"), nil
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
