# BinaryScan

BinaryScan 是面向单位内部多用户的二进制分析工作台。生产环境由九个长期容器组成，支持 Native、JVM/Android 与 Python PYC 三条相互隔离的反编译链路。

当前仓库是全新重构实现，不读取旧仓库数据库和旧运行制品。上传、格式识别、手动归档导入、Trivy、三类反编译、checker 编排、用户管理、审计和 JSON/HTML 报告链路均已接入。九个最终镜像已经完成多角色、故障恢复、停启持久化和备份恢复验收；正式投产前仍须在目标服务器完成实际访问地址、授权网段防火墙、并发容量和物理断网复验。

## 目录边界

- `app`：Go 后端、Vue 前端和五个 Go 进程入口。
- `checkers`：无状态 C、Java、Python 源码检查器。
- `deploy`：产品镜像、开发覆盖和部署脚本。
- `docs`：架构、部署、数据和验收文档。

数据库迁移、worker runtime、API 协议和工具适配均位于所属模块内部，不作为根目录产品模块。

## 生产服务

1. `mysql`
2. `app`
3. `scanner`
4. `native-decompiler`
5. `jvm-decompiler`
6. `pyc-decompiler`
7. `c-checker`
8. `java-checker`
9. `python-checker`

生产 Compose 只引用预构建最终镜像，不包含 `build`。只有 app 发布宿主机端口。

## 首次初始化

1. 检查并提交根目录 `.env` 中的实际访问地址、监听地址、平台和账号配置；该文件含实际密码，仓库权限必须按敏感系统管理。默认 `http://localhost:8080` 仅供服务器本机访问。
2. 初始化数据根：`deploy/scripts/binary.sh init`。
3. 静态检查：`deploy/scripts/binary.sh doctor`。
4. 在制备机准备并验证工具基础镜像：`deploy/scripts/prepare-tools.sh all /srv/binaryscan-tool-cache`。
5. 在制备机构建最终镜像：`deploy/scripts/release.sh build`。
6. 启动：`deploy/scripts/binary.sh up`；该命令会再次执行 `doctor`，不能附加服务名或 Compose 参数，也不能绕过生产检查。

空数据库首次启动时创建固定初始管理员：用户名 `admin`，密码 `admin123456`。账号首次登录后可以直接使用；修改 `.env` 不会重置数据库中已经存在的管理员密码。

管理员可在产品界面的“管理”页创建 reader、operator 或 administrator，停用账号、调整角色、重置密码并查看审计。所有成功更新都会撤销目标账号的现有会话；系统禁止停用或降级当前管理员，也禁止留下零个活跃管理员。

缓存目录不进入 Git，必须随发布证据保存，以便以后用同一批官方资产和 Trivy 数据库重建。详细边界见 `docs/tool-supply-chain.md`。

## 开发

后端：

    cd app/backend
    go test ./...
    go run ./cmd/app

前端：

    cd app/frontend
    npm ci
    npm run dev

开发和生产都使用 HTTP；开发覆盖只额外开放回环 MySQL 端口并允许 Vue 开发服务器的 Origin。

发布 smoke 集中在一个脚本中：`deploy/scripts/smoke.sh topology` 检查九服务边界，`contracts` 对运行中的三个 checker 执行真实 `checker-v1` 请求，`live` 完成一条 PYC 上传、自动 scan/Trivy、手动反编译、手动检查和报告下载链路。完整参数和数据保留边界见 `docs/deployment.md`。

## 数据保证

业务持久化数据只位于 `BINARY_DATA_ROOT/mysql` 和 `BINARY_DATA_ROOT/storage`。`work` 可随时清理，Docker 自身日志与元数据不属于业务备份。

完整说明见 `docs/architecture.md`、`docs/deployment.md` 和 `docs/data-and-backup.md`。
