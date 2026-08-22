# 工具镜像供应链

## 边界

制备机可以联网下载和构建，生产机只能加载预构建的九个最终镜像。Ghidra、JVM 工具、pycdc 和 Trivy 离线库是构建输入，不是长期运行服务，也不进入生产发布包。

工具缓存必须放在 Git 仓库和 `binary-data` 之外，例如 `/srv/binaryscan-tool-cache`。它不是业务数据，但必须随发布证据保存，保证同一版本能够重新构建。

## 固定输入

- Ghidra 12.1.3 官方 PUBLIC ZIP，运行于 JDK 21。
- Vineflower 1.12.0、CFR 0.152、JADX 1.5.6，运行于 JRE 21。
- pycdc 固定到上游提交 `b4289760970dbc399684f1e155ec6d1ea1cc787e`。上游没有正式 release，因此不得把它标记为不存在的 `1.2.0` 版本。
- Trivy 0.74.0 官方容器及制备时缓存的主漏洞数据库和 Java 数据库。

产品运行镜像只保留其能力边界需要的组件。Python checker 只使用标准库，因此不携带 pip/ensurepip；Native worker 只调用 `analyzeHeadless`，构建时会先核对 Ghidra 模块清单，再删除清单明确排除的 GhidraServer YAJSW 服务包装器。两项裁剪都必须通过代表性真实样本和离线漏洞复扫。

精确 URL、基础镜像标签和产品工具镜像标签集中在 `deploy/docker/images.lock.env`。按照本项目的摘要边界，不为每个工具文件新增一套应用级哈希表；官方发布标签、pycdc Git 提交、最终 OCI 镜像身份和离线发布包 SHA-256 共同构成发布记录。

## 制备流程

下载官方资产但暂不构建：

    deploy/scripts/prepare-tools.sh download /srv/binaryscan-tool-cache

下载缺失资产、准备 Trivy 数据库并构建四个工具镜像：

    deploy/scripts/prepare-tools.sh build /srv/binaryscan-tool-cache

执行工具版本和镜像布局检查：

    deploy/scripts/prepare-tools.sh verify /srv/binaryscan-tool-cache

`all` 等价于 build 后再 verify。脚本会复用已经完整下载的文件；下载中断产生的临时文件不会作为有效缓存使用。

## 更新规则

升级任一工具时必须同时修改镜像标签、下载地址、Compose 中记录的工具版本和代表性样本验收记录。Trivy 数据库更新需要使用新的离线镜像标签并重新打包全部最终镜像，生产容器禁止自行更新数据库。

pycdc 的支持范围由固定提交决定。遇到不支持的 PYC 时必须返回失败或 `partial_source`，不能回退到 JVM 容器，也不能伪造完整源码结果。
