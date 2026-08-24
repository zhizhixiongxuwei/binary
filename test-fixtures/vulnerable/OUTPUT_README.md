# 反编译后必须产生 finding 的二进制样本

本目录没有安全零发现样本。4 个二进制均由 BinaryScan 项目 `test-fixtures/vulnerable` 中的故意不安全源码生成：

| 文件 | 反编译器 | checker | 预期规则族 |
| --- | --- | --- | ---: |
| `vulnerable-macho` | Ghidra | c-checker | 4 |
| `VulnerableFixture.class` | Vineflower | java-checker | 13 |
| `vulnerable.jar` | Vineflower | java-checker | 13 |
| `vulnerable.pyc` | pycdc | python-checker | 5 |

`VulnerableFixture.class` 与 `vulnerable.jar` 来自同一份 Java 源码，用于分别覆盖 CLASS 和 JAR 上传路由。`vulnerable-macho` 故意不加扩展名，以覆盖按 magic byte 识别 Mach-O 的真实上传场景。

`expected-findings.json` 是规则 ID 和产物路径的唯一预期清单；`SHA256SUMS` 用于确认样本与元数据未被意外修改。源码含故意不安全调用，只应用于静态分析，不要执行。
