package capability

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"binaryscan.local/backend/internal/checkrules"
	"binaryscan.local/backend/internal/config"
)

var versionPattern = regexp.MustCompile(`\d+\.\d+(?:\.\d+)?(?:\.\d+)?`)

func Collect(ctx context.Context, cfg config.Config) Report {
	now := time.Now().UTC()
	report := Report{Analyzers: []Analyzer{}, Databases: []Database{}}
	switch cfg.Role {
	case "scanner":
		report.Databases = []Database{ProbeDatabase(cfg.Worker.TrivyCacheRoot, "db", "trivy.db", "trivy-db", 2), ProbeDatabase(cfg.Worker.TrivyCacheRoot, "java-db", "trivy-java.db", "trivy-java-db", 1)}
		a := base("scanner", "归档解析、容器漏洞检测", "trivy", now)
		output, err := run(ctx, cfg.Worker.TrivyPath, "--version", "--format", "json")
		var version struct{ Version string }
		if err != nil || json.Unmarshal(output, &version) != nil || version.Version == "" {
			a.Detail = "Trivy 版本命令探测失败"
		} else {
			a.Version, a.RuntimeVersion, a.Status = version.Version, version.Version, "available"
			a.Detail = "Trivy 启动与版本探测通过，双库文件及元数据已检查；未运行完整检测"
			for _, database := range report.Databases {
				if database.Status != "available" {
					a.Status = "unavailable"
					a.Detail = "Trivy 可启动，但离线数据库探测失败"
				}
			}
		}
		report.Analyzers = append(report.Analyzers, a)
		for _, checker := range []struct{ name, url string }{{"c", cfg.Worker.CCheckerURL}, {"java", cfg.Worker.JavaCheckerURL}, {"python", cfg.Worker.PythonCheckerURL}} {
			analyzer := probeChecker(ctx, checker.name, checker.url, now)
			observation := checkrules.Observation{Language: checker.name, Status: "unavailable", Error: "规则目录探测失败"}
			if catalog, err := checkrules.Fetch(ctx, checker.url, checker.name); err == nil {
				observation.Status = "available"
				observation.Error = ""
				observation.Catalog = &catalog
			} else {
				analyzer.Status = "unavailable"
				analyzer.Detail = "Checker 规则目录探测失败，暂不可选择检测规则"
			}
			report.RuleCatalogs = append(report.RuleCatalogs, observation)
			report.Analyzers = append(report.Analyzers, analyzer)
		}
	case "native-decompiler":
		a := base(cfg.Role, "原生二进制反编译", "java", now)
		a.ExpectedVersion = cfg.Worker.ToolVersion
		properties, err := readSmall(filepath.Join(filepath.Dir(filepath.Dir(cfg.Worker.GhidraPath)), "Ghidra", "application.properties"))
		javaOutput, javaErr := run(ctx, cfg.Worker.JavaPath, "-version")
		script, scriptErr := readSmall(filepath.Join(cfg.Worker.GhidraScriptRoot, "ExportPseudoC.java"))
		if err != nil || javaErr != nil || executable(cfg.Worker.GhidraPath) != nil || scriptErr != nil || len(script) == 0 {
			a.Detail = "Ghidra 启动器、导出脚本、版本文件或 Java 启动探测失败"
		} else {
			for _, line := range strings.Split(string(properties), "\n") {
				if strings.HasPrefix(line, "application.version=") {
					a.Version = strings.TrimSpace(strings.TrimPrefix(line, "application.version="))
				}
			}
			a.RuntimeVersion = versionPattern.FindString(string(javaOutput))
			if a.Version != "" {
				a.Status = "available"
				a.Detail = "Ghidra 启动器与版本文件、Java 启动探测通过；未运行完整反编译"
			}
		}
		if a.Status == "available" && a.ExpectedVersion != "" && a.Version != a.ExpectedVersion {
			a.Status = "unavailable"
			a.Detail = "Ghidra 实际版本与配置期望不一致"
		}
		report.Analyzers = append(report.Analyzers, a)
	case "jvm-decompiler":
		a := base(cfg.Role, "Java / Android 反编译", "java", now)
		a.ExpectedVersion = cfg.Worker.ToolVersion
		javaOutput, javaErr := run(ctx, cfg.Worker.JavaPath, "-version")
		vineflower, vineErr := jarVersion(cfg.Worker.VineflowerJar)
		cfrOutput, cfrErr := run(ctx, cfg.Worker.JavaPath, "-jar", cfg.Worker.CFRJar, "--version")
		jadxOutput, jadxErr := run(ctx, cfg.Worker.JavaPath, "-cp", cfg.Worker.JADXJar, "jadx.cli.JadxCLI", "--version")
		cfr, jadx := versionPattern.FindString(string(cfrOutput)), versionPattern.FindString(string(jadxOutput))
		if javaErr != nil || vineErr != nil || cfrErr != nil || jadxErr != nil || cfr == "" || jadx == "" {
			a.Detail = "Java 或 Vineflower / CFR / JADX 工具探测失败"
		} else {
			a.Version = "vineflower-" + vineflower + "+cfr-" + cfr + "+jadx-" + jadx
			a.RuntimeVersion = versionPattern.FindString(string(javaOutput))
			a.Status = "available"
			a.Detail = "Java 启动、Vineflower 版本清单及 CFR / JADX 版本命令通过；未运行完整反编译"
			if a.ExpectedVersion != "" && a.Version != a.ExpectedVersion {
				a.Status = "unavailable"
				a.Detail = "JVM 工具实际版本与配置期望不一致"
			}
		}
		report.Analyzers = append(report.Analyzers, a)
	case "pyc-decompiler":
		a := base(cfg.Role, "Python 字节码反编译", "pycdc", now)
		a.ExpectedVersion = cfg.Worker.ToolVersion
		output, err := run(ctx, cfg.Worker.PYCDCPath, "--help")
		if err == nil && bytes.Contains(output, []byte("Usage:")) {
			a.Status = "available"
			a.Detail = "pycdc 可执行与帮助命令探测通过；工具未提供可核实版本，未运行完整反编译"
		} else {
			a.Detail = "pycdc 启动探测失败"
		}
		report.Analyzers = append(report.Analyzers, a)
	}
	return report
}

func base(name, scope, runtime string, now time.Time) Analyzer {
	return Analyzer{Name: name, Status: "unavailable", Scope: scope, RuntimeName: runtime, Verification: "probe", LastCheckedAt: now}
}

type cappedBuffer struct{ bytes.Buffer }

func (b *cappedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if b.Len() < 64<<10 {
		remaining := (64 << 10) - b.Len()
		if len(p) > remaining {
			p = p[:remaining]
		}
		_, _ = b.Buffer.Write(p)
	}
	return n, nil
}
func run(parent context.Context, path string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, path, args...)
	var output cappedBuffer
	command.Stdout = &output
	command.Stderr = &output
	err := command.Run()
	return output.Bytes(), err
}

func executable(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return fmt.Errorf("not executable")
	}
	return nil
}
func readSmall(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	if len(data) > 64<<10 {
		return nil, fmt.Errorf("metadata too large")
	}
	return data, err
}

func jarVersion(path string) (string, error) {
	jar, err := zip.OpenReader(path)
	if err != nil {
		return "", err
	}
	defer jar.Close()
	for _, file := range jar.File {
		if file.Name != "META-INF/MANIFEST.MF" {
			continue
		}
		reader, err := file.Open()
		if err != nil {
			return "", err
		}
		data, err := io.ReadAll(io.LimitReader(reader, 64<<10))
		reader.Close()
		if err != nil {
			return "", err
		}
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "Implementation-Version:") {
				version := strings.TrimSpace(strings.TrimPrefix(line, "Implementation-Version:"))
				if version != "" {
					return version, nil
				}
			}
		}
	}
	return "", fmt.Errorf("jar version unavailable")
}

func probeChecker(ctx context.Context, name, url string, now time.Time) Analyzer {
	a := base(name+"-checker", strings.ToUpper(name)+" 源码检测", "http", now)
	if url == "" {
		a.Status = "unknown"
		a.Detail = "未配置 Checker 地址"
		return a
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(url, "/")+"/healthz", nil)
	if err != nil {
		a.Detail = "Checker 地址配置无效"
		return a
	}
	client := http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		a.Detail = "Checker 健康端点不可访问"
		return a
	}
	defer response.Body.Close()
	var result struct {
		Status  string
		Checker string
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&result) != nil || result.Status != "ok" || result.Checker != name {
		a.Detail = "Checker 健康响应校验失败"
		return a
	}
	a.Status = "available"
	a.Detail = "健康端点探测通过；服务未报告版本，未运行完整规则检测"
	return a
}

func ProbeDatabase(root, directory, filename, name string, expectedSchema int) Database {
	result := Database{Name: name, Status: "unavailable", Path: filepath.Join(root, directory, filename)}
	parent, err := os.Lstat(filepath.Join(root, directory))
	if err != nil || !parent.IsDir() {
		result.Error = "数据库目录不存在或不是普通目录"
		return result
	}
	file, err := os.Lstat(result.Path)
	if err != nil || !file.Mode().IsRegular() || file.Size() <= 0 {
		result.Error = "数据库文件不存在、为空或不是普通文件"
		return result
	}
	result.SizeBytes = file.Size()
	content, err := os.Open(result.Path)
	if err != nil {
		result.Error = "数据库文件不可读取"
		return result
	}
	var firstByte [1]byte
	_, err = io.ReadFull(content, firstByte[:])
	_ = content.Close()
	if err != nil {
		result.Error = "数据库文件不可读取"
		return result
	}
	body, err := readSmall(filepath.Join(root, directory, "metadata.json"))
	if err != nil {
		result.Error = "数据库元数据不可读取"
		return result
	}
	var metadata struct {
		Version      int
		UpdatedAt    time.Time
		NextUpdate   time.Time
		DownloadedAt time.Time
	}
	if json.Unmarshal(body, &metadata) != nil {
		result.Error = "数据库元数据格式无效"
		return result
	}
	result.SchemaVersion = &metadata.Version
	if !metadata.UpdatedAt.IsZero() {
		result.UpdatedAt = &metadata.UpdatedAt
	}
	if !metadata.NextUpdate.IsZero() {
		result.NextUpdate = &metadata.NextUpdate
	}
	if !metadata.DownloadedAt.IsZero() {
		result.DownloadedAt = &metadata.DownloadedAt
	}
	if metadata.Version != expectedSchema {
		result.Error = "不兼容的数据库 schema：" + strconv.Itoa(metadata.Version)
		return result
	}
	if metadata.UpdatedAt.IsZero() || metadata.UpdatedAt.After(time.Now().UTC().Add(5*time.Minute)) {
		result.Error = "数据库更新时间缺失或在未来"
		return result
	}
	// This intentionally does not claim cryptographic integrity or a completed
	// scan: metadata/schema and nonempty regular files are what was inspected.
	result.Status = "available"
	return result
}
