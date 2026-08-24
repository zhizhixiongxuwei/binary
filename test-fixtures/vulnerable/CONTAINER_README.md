# 可手动触发 Trivy 的容器镜像样本

| 文件 | 服务端格式 | 结构 |
| --- | --- | --- |
| `docker-save.tar` | `docker-tar` | Docker Save archive |
| `docker-save.img` | `docker-tar` | 与 Docker Save TAR 字节相同，仅扩展名改为 IMG |
| `oci-layout.tar` | `oci-tar` | OCI Image Layout archive |

三个文件由同一个确定性 layer 生成，layer 内含 `01-binary` 的 10 个结果型二进制，并额外放置一个只含 Maven 元数据的合成 `log4j-core 2.14.1` JAR。该 JAR 不含 Log4j 可执行代码，只用于让离线 Trivy Java 数据库稳定产生漏洞结果。

`expected-trivy.json` 记录三个上传文件、预期包版本、最低 finding 数和必须出现的稳定 CVE 集合；允许离线数据库升级后新增漏洞，但缺失这些基准 CVE 会使镜像回归失败。

上传时必须选择容器镜像分类。系统只创建容器任务，不自动运行 Trivy；由用户在任务页手动触发镜像漏洞扫描。

Docker/OCI 的离线文件标准载体是 TAR。`docker-save.img` 是为固定验收要求准备的明确测试特例；系统仍依据内部 Docker manifest 识别，不会把任意 IMG 当作容器镜像。
