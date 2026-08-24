# 可展开并批量创建任务的归档/文件系统镜像

本目录覆盖 12 种可执行的一层归档/文件系统导入样本。普通复合归档直接包含 ELF 与 PE，流式压缩和系统包至少直接产出一个 ELF，JAR/APK 分别产出 CLASS/DEX。

| 文件 | 服务端格式 | 一层展开结果 |
| --- | --- | --- |
| `vulnerable-binaries.zip` | `zip` | ELF + PE |
| `vulnerable-binaries.7z` | `7z` | ELF + PE |
| `vulnerable-binaries.rar` | `rar` | ELF + PE |
| `vulnerable-binaries.tar` | `tar` | ELF + PE |
| `vulnerable-elf.gz` | `gzip` | ELF |
| `vulnerable-elf.xz` | `xz` | ELF |
| `vulnerable-binaries.deb` | `deb` | ELF |
| `vulnerable-binaries.rpm` | `rpm` | ELF |
| `vulnerable-binaries.iso` | `iso9660` | ELF + PE |
| `vulnerable-binaries.ext4` | `ext4` | ELF + PE |
| `vulnerable-binaries.jar` | `jar`/ZIP | CLASS |
| `vulnerable-binaries.apk` | `apk`/ZIP | DEX |

ISO 9660 和 EXT4 是文件系统镜像，不是压缩算法；产品对它们提供安全、只读、不挂载的“一层枚举 → 批量创建二进制任务”归档模式。二者均不送入 Trivy，容器模式会明确显示“不适用/无结果”。

ISO 主卷可能显示大写文件标识符；文件内容与 `01-binary` 中的 ELF/PE 相同，服务端仍按 magic byte 正确识别。

`.img` 本身不是格式；Docker Save 改名样本放在 `03-container/docker-save.img`，由内容识别为 `docker-tar`。
