# BinaryScan 故意含漏洞的检测夹具

本目录中的文件只用于离线验证“上传 → 反编译 → 源码检测 → 报告 → Monaco 源码定位”流程，代码不会在生成或检测过程中执行。

- `vulnerable-macho`：Native/Mach-O，经 Ghidra 后稳定命中 `cwe-120-bounds`、`cwe-252-unchecked-return`、`cwe-732-permissions`、`cwe-78-command`。
- `VulnerableFixture.class`、`vulnerable.jar`：JVM，经 Vineflower 后覆盖移植的全部 13 个 Java 规则族。
- `vulnerable.pyc`：Python 3.9 checked-hash PYC，经 pycdc 后覆盖移植的全部 5 个 Python 规则族，包括 pycdc 特有的关键字还原形式。
- `vulnerable-binaries.zip`：位于 `02-archive`，第一层包含上述二进制，用于验证归档自动拆分和批量生成二进制任务。
- `expected-findings.json`：上述产物与预期规则 ID 的机器可读清单，实时 checker 回归直接读取该文件。

这些文件与 `01-binary` 下原有的安全格式夹具分开放置。安全夹具预期 0 条发现；本目录夹具预期产生发现。

C checker 的全部 15 个规则族仍由源码级单元测试覆盖。数组边界、`sizeof(pointer)` 等源码事实在编译成机器码后可能不可逆丢失，因此没有把它们错误列为 Ghidra 端到端的必现规则。
