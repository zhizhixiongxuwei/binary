# BinaryScan

BinaryScan 是面向单位内部多用户的二进制分析工作台。生产环境由九个长期容器组成，支持 Native、JVM/Android 与 Python PYC 三条相互隔离的反编译链路。

当前仓库是全新重构实现，不读取旧仓库数据库和旧运行制品。上传、格式识别、手动归档导入、Trivy、三类反编译、checker 编排和 JSON/HTML 报告链路均已接入。九个最终镜像、四类离线工具输入和代表性样本已完成制备机验收；正式投产前仍须完成目标服务器上的多用户、TLS、备份恢复和断网重启验收。

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

1. 检查并提交根目录 `.env` 中的正式域名、证书路径、平台和账号配置；该文件含实际密码，仓库权限必须按敏感系统管理。
2. 把单位 CA 签发的证书放到 `BINARY_DATA_ROOT/tls/server.crt`，私钥放到 `BINARY_DATA_ROOT/tls/server.key`。
3. 初始化数据根：`deploy/scripts/binary.sh init`。
4. 静态检查：`deploy/scripts/binary.sh doctor`。
5. 在制备机准备并验证工具基础镜像：`deploy/scripts/prepare-tools.sh all /srv/binaryscan-tool-cache`。
6. 在制备机构建最终镜像：`deploy/scripts/release.sh build`。
7. 启动：`deploy/scripts/binary.sh up`。

初始管理员只在空数据库中创建一次。首次登录后必须修改密码，修改 `.env` 不会重置数据库中的管理员密码。

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

开发入口使用 `deploy/docker/compose.dev.yml` 覆盖为本机 HTTP；生产仍使用根 `docker-compose.yml` 的 HTTPS 入口。

## 数据保证

业务持久化数据只位于 `BINARY_DATA_ROOT/mysql` 和 `BINARY_DATA_ROOT/storage`。`work` 可随时清理，Docker 自身日志与元数据不属于业务备份。

完整说明见 `docs/architecture.md`、`docs/deployment.md` 和 `docs/data-and-backup.md`。
