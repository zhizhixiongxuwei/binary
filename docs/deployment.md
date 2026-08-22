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

`BINARY_DATA_ROOT` 必须是绝对路径，且不得位于 Git 仓库内、包含 Git 仓库、使用符号链接或指向文件系统根目录。生产启动统一使用无附加参数的 `deploy/scripts/binary.sh up`：入口固定使用仓库根 `docker-compose.yml`，拒绝服务名和 Compose 选项，先强制执行 `doctor`，通过后才以 `--pull never` 启动完整九服务，并移除同一 Compose 项目中已不属于正式拓扑的旧 orphan 容器。该收敛不删除 bind mount 中的业务数据，但旧容器自身的 Docker 日志和元数据不保留。调用环境中的 `COMPOSE_FILE` 不能替换产品拓扑。开发覆盖由专用开发文件启动，恢复演练使用隔离的 Compose 项目；二者都不经过生产入口。

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

## 发布 smoke

`deploy/scripts/smoke.sh` 是唯一发布 smoke 驱动，不建立大型测试树：

- `topology`：静态确认服务集合恰好为九个。
- `contracts`：在运行栈的 `checker-net` 上临时启动最终 Python checker 镜像作为 HTTP 客户端，对 C、Java、Python 三个 checker 发送真实 `checker-v1` 请求并核对代表性规则。临时容器使用 `--pull never`、只读根文件系统且不挂载业务数据。
- `live`：上传内嵌的小型 Python 3.9 PYC，确认只有 scan 和 Trivy 自动运行，再依次手动触发 pycdc、Python checker 和 JSON 报告下载。
- `all`：依次执行以上三项。

`contracts` 默认连接 `.env` 中 `COMPOSE_PROJECT_NAME` 对应的运行栈；隔离验收项目可用 `BINARY_SMOKE_PROJECT` 指定。`live` 需要一个已完成首次换密的 operator 或 administrator，凭据只通过进程环境临时提供，不写入 `.env`、参数或测试文件：

    export BINARY_SMOKE_USERNAME=release-smoke
    read -r -s BINARY_SMOKE_PASSWORD
    export BINARY_SMOKE_PASSWORD
    export BINARY_SMOKE_BASE_URL=https://binaryscan.unit.example
    export BINARY_SMOKE_CA_CERT=/path/to/unit-ca.crt   # 系统已信任单位 CA 时省略
    deploy/scripts/smoke.sh all
    unset BINARY_SMOKE_PASSWORD

`live` 对非回环目标强制 HTTPS；HTTP 只接受严格的 `localhost`、`127.0.0.1` 或 `[::1]` 加可选端口。脚本禁用用户 `.curlrc` 和代理环境，防止本机配置改变证书、重定向、日志或回环传输边界。`BINARY_SMOKE_TIMEOUT_SECONDS` 默认每个异步等待阶段 600 秒。仅在使用 HTTPS 且没有正式 DNS 的隔离验收环境中，才可通过 `BINARY_SMOKE_RESOLVE=host:port:address` 指定 curl 的临时解析；这不会关闭证书校验，回环 HTTP 不接受该选项。`live` 只有在成功注销自身 session 后才报告通过；异常退出时也会尽力注销并在失败时告警。它有意保留创建的 task、runs、finding 和 report 作为发布证据，不应在正式业务库中高频执行。
