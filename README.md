# BinaryScan

二进制分析工作台：Go API 和 Vue 前端、异步扫描与反编译 Worker，以及 C / Java / Python 源码检查器。运行环境包含 9 个服务，仅 App 对外开放端口。

## 目录

```text
app/                      # Go 后端、Vue 前端、App 镜像
checkers/                 # C、Java、Python 无状态检查器及各自镜像
deploy/
  docker/                 # Worker Dockerfile、基础镜像版本、开发 Compose 覆盖
  tools/                  # Ghidra / JVM / pycdc / Trivy 工具镜像配方
  delivery/               # 交付包部署模板；demo 为旧源码验真模板
script/
  build-local/            # build.sh / build.ps1 → 根目录 local/
  build-release/          # build.sh / build.ps1 → 根目录 release/
  lib/                    # 共用打包实现及按服务构建辅助脚本
  tools/                  # 工具镜像准备
  ops/                    # 原根目录 Compose 运维、外部数据备份恢复
  tests/                  # 打包测试、smoke、运行回归
  fixtures/               # 测试样例生成
  legacy/                 # 原 binary-deploy / binary-demo 双交付入口
docs/                     # 架构分析与构建部署说明
docker-compose.yml        # 9 服务运行拓扑的唯一来源
.env                      # 构建与原根目录部署配置
local/                    # 生成的本机运行目录，不提交 Git
release/                  # 生成的离线交付目录，不提交 Git
```

`deploy` 保留镜像配方和交付模板；原 `deploy/scripts` 已全部迁入 `script`。核心代码继续归属于 `app` 和 `checkers`，打包不改变业务模块。

## 本地打包

构建机需要 Python 3.10+、Docker（Linux 容器）和 Docker Compose v2。默认构建 `linux/amd64`，首次构建需要联网下载基础镜像、工具、漏洞库与语言依赖。

Windows PowerShell：

```powershell
.\script\build-local\build.ps1
cd local
docker compose up -d --wait
```

Linux / macOS：

```sh
sh script/build-local/build.sh
cd local
docker compose up -d --wait
```

脚本构建 8 个产品镜像并准备 MySQL 镜像，生成 Compose、配置、管理脚本和已初始化的数据目录。`local` 使用构建机 Docker 中的镜像，不额外导出 tar。默认访问 `http://localhost:8080`；若修改了根配置，以包内 `.env` 为准。初始管理员密码在生成目录的 `.env` 中，每个新包独立生成。

## 离线交付

在联网构建机执行：

```powershell
.\script\build-release\build.ps1
```

或：

```sh
sh script/build-release/build.sh
```

把整个 `release/` 目录交给客户。目标机预先安装并启动 Docker、Compose v2，使用 Linux 容器；不需要 Python、Go、Node、Java 或源码。在目标目录中执行：

```powershell
# Windows PowerShell
.\install.ps1
```

```sh
# Linux
sudo sh install.sh
# macOS
sh install.sh
```

安装脚本依次校验交付文件、导入全部 9 个运行镜像、初始化数据权限、启动并等待服务健康。启动禁止拉取镜像及现场构建。Trivy 两个数据库和反编译工具已随最终运行镜像封装。

已构建好镜像时，可对任一打包入口追加 `--skip-build`，只检查和打包本机已有镜像。脚本拒绝覆盖已存在的 `local/` 或 `release/`；重新打包前应先停止旧包服务并将旧目录移到其他位置保留，尤其不要删除已有 `data/`。

完整说明：[构建与离线部署](docs/build-and-deployment.md) · [代码架构及目录设计](docs/architecture.md)。

## 开发与验证

```sh
python -m unittest discover -s script/tests -p "test_*.py" -v
cd app/backend
go test ./...
```

```sh
cd app/frontend
npm ci
npm test
npm run build
```

`script/tests/smoke.sh` 保留原有 `topology`、`contracts`、`live` 检查；运行回归需要已启动的服务和相应测试样例，详见部署说明。
