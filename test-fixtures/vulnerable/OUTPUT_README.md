# 反编译后必须产生 finding 的二进制样本

本目录没有安全零发现样本。10 个二进制均由 BinaryScan 项目 `test-fixtures/vulnerable` 中的故意不安全源码生成：

| 文件 | 反编译器 | checker | 预期规则族 |
| --- | --- | --- | ---: |
| `vulnerable.exe` | Ghidra | c-checker | 5 |
| `vulnerable.dll` | Ghidra | c-checker | 6 |
| `vulnerable.sys` | Ghidra | c-checker | 5 |
| `vulnerable-elf` | Ghidra | c-checker | 4 |
| `vulnerable-macho` | Ghidra | c-checker | 4 |
| `VulnerableFixture.class` | Vineflower | java-checker | 13 |
| `vulnerable.jar` | Vineflower | java-checker | 13 |
| `vulnerable.dex` | JADX | java-checker | 2 |
| `vulnerable.apk` | JADX | java-checker | 2 |
| `vulnerable.pyc` | pycdc | python-checker | 5 |

EXE、DLL 与 SYS 是真实 PE32+ 文件，其中 SYS 使用 native subsystem；ELF 与 Mach-O 也是实际可执行格式。CLASS/JAR 与 DEX/APK 分别来自同一组 Java/Smali 源码，用于覆盖对应上传和反编译路由。所有判断以 magic byte 和结构为准，不依赖扩展名伪造。

`expected-findings.json` 是规则 ID 和产物路径的唯一预期清单；`SHA256SUMS` 用于确认样本与元数据未被意外修改。源码含故意不安全调用，只应用于静态分析，不要执行。
