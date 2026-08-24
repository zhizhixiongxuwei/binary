# 可手动触发 Trivy 的容器镜像样本

| 文件 | 服务端格式 | 结构 |
| --- | --- | --- |
| `docker-save.tar` | `docker-tar` | Docker Save archive |
| `oci-layout.tar` | `oci-tar` | OCI Image Layout archive |

两个镜像由同一个确定性 layer 生成，layer 内含 `01-binary` 的 4 个结果型二进制，并额外放置一个只含 Maven 元数据的合成 `log4j-core 2.14.1` JAR。该 JAR 不含 Log4j 可执行代码，只用于让离线 Trivy Java 数据库稳定产生漏洞结果。

`expected-trivy.json` 记录两种镜像路径、预期包版本、最低 finding 数和必须出现的稳定 CVE 集合；允许离线数据库升级后新增漏洞，但缺失这些基准 CVE 会使镜像回归失败。

上传时必须选择容器镜像分类。系统只创建容器任务，不自动运行 Trivy；由用户在任务页手动触发镜像漏洞扫描。

Docker/OCI 的离线文件标准载体是 TAR。`.img` 只是通用磁盘镜像扩展名，不应通过改名伪装成容器镜像。
