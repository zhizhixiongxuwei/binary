package app

import "strings"

// These labels only affect human-readable reports. The snapshot and raw
// diagnostic identities retain the actual tools and their versions.
func reportRunKindText(value any) string {
	labels := map[string]string{
		"scan": "文件识别与解析", "archive_import": "归档解析",
		"trivy_scan": "镜像漏洞检测", "native_decompile": "原生二进制反编译",
		"jvm_decompile": "Java / Android 反编译", "pyc_decompile": "Python 字节码反编译",
		"c_check": "C/C++ 源码检测", "c_sast": "C/C++ 源码检测",
		"java_check": "Java 源码检测", "java_sast": "Java 源码检测",
		"python_check": "Python 源码检测", "python_sast": "Python 源码检测",
	}
	if label, ok := labels[reportText(value)]; ok {
		return label
	}
	return reportDisplayText(value)
}

func reportToolText(run map[string]any) string {
	labels := map[string]string{
		"trivy": "漏洞检测引擎", "scanner": "漏洞检测引擎",
		"ghidra": "原生二进制反编译引擎", "native-decompiler": "原生二进制反编译引擎",
		"vineflower": "Java 反编译引擎", "cfr": "Java 反编译引擎",
		"jadx": "Android 反编译引擎", "jvm-decompiler": "Java / Android 反编译引擎",
		"pycdc": "Python 字节码反编译引擎", "pyc-decompiler": "Python 字节码反编译引擎",
		"python-bytecode": "Python 字节码反编译引擎",
		"c-checker":       "C/C++ 源码检测引擎", "java-checker": "Java 源码检测引擎",
		"python-checker":             "Python 源码检测引擎",
		"binaryscan-format-detector": "文件识别引擎", "binaryscan-archive-importer": "归档解析引擎",
	}
	name := strings.TrimSpace(reportText(run["toolName"]))
	if label, ok := labels[strings.ToLower(name)]; ok {
		return label
	}
	if name == "" {
		return "—"
	}
	return name
}
