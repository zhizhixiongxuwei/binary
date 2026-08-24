# BinaryScan 故意含漏洞的检测夹具

本目录中的文件只用于离线验证“上传 → 反编译 → 源码检测 → 报告 → Monaco 源码定位”流程，代码不会在生成或检测过程中执行。

- `vulnerable-macho`：Native/Mach-O，预期命中不安全复制、动态命令和宽松权限规则。
- `VulnerableFixture.class`、`vulnerable.jar`：JVM，覆盖 Java 13 个规则族中的标准 JDK 可编译场景。
- `vulnerable.pyc`：Python 3.9 checked-hash PYC，覆盖 Python 5 个规则族。
- `vulnerable-binaries.zip`：位于 `02-archive`，第一层包含上述二进制，用于验证归档自动拆分和批量生成二进制任务。

这些文件与 `01-binary` 下原有的安全格式夹具分开放置。安全夹具预期 0 条发现；本目录夹具预期产生发现。
