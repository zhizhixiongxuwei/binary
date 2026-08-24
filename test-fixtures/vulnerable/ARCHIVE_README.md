# 可展开并批量创建任务的归档/文件系统镜像

本目录中的 ZIP、ISO 和 IMG 都只包含 `01-binary` 下的 4 个结果型二进制。

| 文件 | 服务端格式 | 上传分类 | 预期行为 |
| --- | --- | --- | --- |
| `vulnerable-binaries.zip` | `zip` | 归档 | 自动展开一层，列出 4 个二进制 |
| `vulnerable-binaries.iso` | `iso9660` | 归档 | 枚举 ISO 9660 文件系统，列出 4 个二进制 |
| `vulnerable-binaries.img` | `iso9660` | 归档 | 与 ISO 字节相同，用于验证 `.img` 不能只按扩展名分类 |

ISO 9660 是光盘文件系统镜像，不是压缩算法；但它与压缩包使用相同的“只展开一层 → 枚举文件 → 批量创建二进制任务”工作流，因此归入产品的归档导入分类，而不是容器 Trivy 分类。

ISO 主卷使用标准的大写文件标识符，因此枚举出的名称会显示为 `VULNERABLE-MACHO`、`VULNERABLE.JAR`、`VULNERABLE.PYC` 和 `VULNERABLEFIXTURE.CLASS`；文件内容与 `01-binary` 中的对应样本相同，服务端仍按 magic byte 正确识别。

`.img` 本身不是格式。本样本明确是一个使用 `.img` 扩展名的 ISO 9660 原始镜像；EXT2/3/4、MBR/GPT 等其他 `.img` 内容需要独立的 magic-byte 与文件系统解析能力，不能据扩展名猜测。
