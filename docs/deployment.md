# 部署

## 网络入口

标准模式由 app 直接终止 TLS。`.env` 中必须设置正式 `PUBLIC_BASE_URL`、监听地址、允许 Origin 和单位 CA 证书路径。

防火墙只允许单位授权网段访问 app 的 HTTPS 端口。MySQL、worker 和 checker 不得发布宿主机端口。

如果单位已有 HTTPS 网关，可把 `APP_TLS_MODE` 改为 `proxy`，只配置实际代理 CIDR，并把 app upstream 限制为代理主机可达。不得信任任意 `X-Forwarded-*` 来源。

## 配置

根 `.env` 是唯一实际部署配置并提交 Git；没有 `.env.example`。`deploy/docker/images.lock.env` 只描述制备机构建输入，不是第二份运行配置。

Compose 对每个服务显式注入变量，不使用全量 `env_file`。checker 不会得到数据库密码、session key或初始管理员密码。

获取仓库等同于获取该部署的凭据。仓库权限必须按敏感系统管理，脚本和日志不得打印展开后的 Compose 配置。

Linux 生产机首次创建数据目录时使用 `sudo deploy/scripts/binary.sh init`。脚本会把 `storage`、`work` 和 `tls` 交给 `.env` 中固定的产品 UID/GID；MySQL 目录仍由官方镜像入口自行初始化。证书若在初始化后复制进去，需要确保 `PRODUCT_UID` 能读取证书和私钥。

启动前必须执行 `deploy/scripts/binary.sh doctor`；Linux 上若部署账号不属于 `PRODUCT_GID`，应使用 `sudo deploy/scripts/binary.sh doctor`。它会拒绝生产 HTTP 模式、占位 URL、权限过宽的 `.env`、缺失或产品 UID/GID 不可访问的数据目录、缺失或权限不安全的 direct-TLS 私钥，以及缺失或平台不匹配的九个生产镜像。direct-TLS 私钥应由产品 UID 独占读取（例如 `0600`），或仅向 `PRODUCT_GID` 开放组读取（例如 `0640`）；不得向其他用户开放。`proxy` 模式必须配置实际网关 CIDR，不能信任全网段。开发环境和回环恢复演练可以直接使用 Compose 的 HTTP 模式，但不能通过生产 doctor。

`BINARY_DATA_ROOT` 必须是绝对路径，且不得位于 Git 仓库内、包含 Git 仓库、使用符号链接或指向文件系统根目录。生产启动统一使用 `deploy/scripts/binary.sh up`，该入口固定 `--pull never`。

## 账号与审计

空数据库首次启动时只创建 `.env` 指定的初始 administrator，并强制首次登录修改密码。后续账号只能由 administrator 在产品“管理”页维护；角色含 reader、operator 和 administrator。reader 可以查询任务、finding 和报告，operator 还可以上传并手动触发运行，administrator 额外管理账号和查看审计。

创建用户、角色/启停更新、密码重置、RBAC/CSRF 拒绝和最后管理员保护都会留下审计结果。密码重置后目标用户必须在下次登录修改密码，且所有旧 session 立即失效；审计不记录明文密码、密码哈希、session token 或 CSRF token。

密码长度按 UTF-8 编码后的字节数计算，范围为 12–72 字节。

## 离线交付

制备机负责构建八个产品镜像并连同 MySQL 镜像打包。制备机先执行：

    deploy/scripts/prepare-tools.sh all /srv/binaryscan-tool-cache
    deploy/scripts/release.sh build
    mkdir -p /srv/binaryscan-release
    deploy/scripts/release.sh package /srv/binaryscan-release/binary-runtime-0.1.0-dev-amd64.tar

第一条命令从官方发布源取得并缓存 Ghidra、Vineflower、CFR、JADX、pycdc 源码，以及 Trivy 主数据库和 Java 数据库。缓存不进入 Git，但必须与本次发布记录一起保存。生产机只执行：

    deploy/scripts/release.sh load /srv/binaryscan-release/binary-runtime-0.1.0-dev-amd64.tar
    deploy/scripts/binary.sh doctor
    deploy/scripts/binary.sh up

归档和同名 `.sha256` 必须放在同一目录。`release.sh load` 会先在归档所在目录校验，再执行 `docker load`，因此不依赖调用命令时的当前工作目录。

生产机不得执行 build、pull、npm、Maven、pip 或 Trivy 数据库更新。

worker Dockerfile 使用固定的 Ghidra、JVM tools、pycdc 和 Trivy 离线基础镜像。这四个基础镜像只存在于制备机，不进入生产发布包。归档导入由 scanner 内的 Go 实现负责，不再维护额外的 archive-tools 镜像。
