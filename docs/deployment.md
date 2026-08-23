# 部署

## 网络入口

产品入口只提供 HTTP，不加载证书，也不信任 `X-Forwarded-*` 代理头。根 `.env` 默认把 app 绑定到 `127.0.0.1:8080`，用户可在服务器本机通过 `http://localhost:8080` 访问。

需要让单位其他用户访问时，把 `PUBLIC_BASE_URL` 和 `APP_ALLOWED_ORIGINS` 改为实际 HTTP 地址，把 `APP_BIND_IP` 改为服务器固定内网地址或 `0.0.0.0`，并只允许授权网段访问 `APP_PORT`。MySQL、worker 和 checker 不得发布宿主机端口。

HTTP 会明文传输登录口令、session、上传文件和报告，因此不得直接暴露到互联网或不可信网络。若以后重新引入 HTTPS，应作为新的部署边界设计，不能仅靠设置未受信代理头实现。

## 配置

根 `.env` 是唯一实际部署配置并提交 Git；没有 `.env.example`。`deploy/docker/images.lock.env` 只描述制备机构建输入，不是第二份运行配置。

Compose 对每个服务显式注入变量，不使用全量 `env_file`。checker 不会得到数据库密码、session key或初始管理员密码。

获取仓库等同于获取该部署的凭据。仓库权限必须按敏感系统管理，脚本和日志不得打印展开后的 Compose 配置。

Linux 生产机首次创建数据目录时使用 `sudo deploy/scripts/binary.sh init`。脚本会把 `storage` 和 `work` 交给 `.env` 中固定的产品 UID/GID；MySQL 目录仍由官方镜像入口自行初始化。

启动前必须执行 `deploy/scripts/binary.sh doctor`；Linux 上若部署账号不属于 `PRODUCT_GID`，应使用 `sudo deploy/scripts/binary.sh doctor`。它要求 `PUBLIC_BASE_URL` 使用 HTTP 且只包含主机和可选端口，要求 `APP_ALLOWED_ORIGINS` 精确包含该地址，并检查 `.env` 权限、数据目录、外部端口以及九个镜像的平台。默认 localhost 配置可以直接通过；切换为局域网地址后仍须由部署人员确认服务器防火墙。

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
    deploy/scripts/release.sh package /srv/binaryscan-release/binary-runtime-0.1.0-dev-amd64-http.tar

第一条命令从官方发布源取得并缓存 Ghidra、Vineflower、CFR、JADX、pycdc 源码，以及 Trivy 主数据库和 Java 数据库。缓存不进入 Git，但必须与本次发布记录一起保存。生产机只执行：

    deploy/scripts/release.sh load /srv/binaryscan-release/binary-runtime-0.1.0-dev-amd64-http.tar
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
    export BINARY_SMOKE_BASE_URL=http://localhost:8080
    deploy/scripts/smoke.sh all
    unset BINARY_SMOKE_PASSWORD

`live` 只接受 HTTP 地址，并拒绝 URL 中的用户信息、路径、查询和 fragment。脚本禁用用户 `.curlrc` 和代理环境，防止本机配置改变重定向、日志或传输目标。`BINARY_SMOKE_TIMEOUT_SECONDS` 默认每个异步等待阶段 600 秒。`live` 只有在成功注销自身 session 后才报告通过；异常退出时也会尽力注销并在失败时告警。它有意保留创建的 task、runs、finding 和 report 作为发布证据，不应在正式业务库中高频执行。
