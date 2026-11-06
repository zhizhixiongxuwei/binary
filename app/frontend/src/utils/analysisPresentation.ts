/** Product labels only. Protocol identifiers and diagnostic records stay unchanged. */
const engineLabels: Readonly<Record<string, string>> = {
  trivy: '漏洞检测引擎', scanner: '漏洞检测引擎',
  ghidra: '原生二进制反编译引擎', 'ghidra-pseudoc': '原生二进制反编译引擎',
  'native-decompiler': '原生二进制反编译引擎',
  vineflower: 'Java 反编译引擎', cfr: 'Java 反编译引擎',
  jadx: 'Android 反编译引擎', 'jvm-decompiler': 'Java / Android 反编译引擎',
  pycdc: 'Python 字节码反编译引擎', 'python-bytecode': 'Python 字节码反编译引擎',
  'pyc-decompiler': 'Python 字节码反编译引擎',
  'c-checker': 'C/C++ 源码检测引擎', 'java-checker': 'Java 源码检测引擎',
  'python-checker': 'Python 源码检测引擎',
}

export function analysisEngineLabel(value: string | null | undefined, fallback = '分析引擎'): string {
  const name = value?.trim() ?? ''
  return engineLabels[name.toLowerCase()] ?? (name ? analysisMessage(name) : fallback)
}

/** Only use on system-generated prose, never source text, evidence, IDs or paths. */
export function analysisMessage(value: string | null | undefined): string {
  return (value ?? '').replace(/\b(?:trivy|ghidra|vineflower|cfr|jadx|pycdc)\b/gi,
    (name) => analysisEngineLabel(name))
}
