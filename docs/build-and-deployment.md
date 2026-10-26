# 构建与离线部署

## 构建流程

两种入口共用 `script/lib/build.py`，输入为当前工作树、根 `.env`、`deploy/docker/images.lock.env`。默认构建 8 个产品镜像并准备 MySQL，检查 9 个镜像的平台，最后生成目录。

| 内容 | local | release |
| --- | --- | --- |
| Compose、配置、管理脚本 | 有 | 有 |
| 镜像归档 | 无，使用构建机镜像 | 全部 9 个运行镜像 |
| 数据目录 | 构建时初始化 | 客户安装时初始化 |
| 用途 | 构建机直接启动 | 复制给离线客户 |

构建机需要 Python 3.10+、Docker Linux 容器及支持 `up --wait` 的 Compose v2。Python 实现仅使用标准库。当前工具制备限定 `linux/amd64`；其他 CPU 上的 Docker 必须预先具备对应模拟能力。客户机器只需 Docker、Compose，不需要 Python 或任何编译工具。

构建入口会先准备产品镜像所需的外部基础镜像，再制备工具或编译产品；工具制备也使用相同的拉取策略检查其基础镜像。平台匹配的本地镜像直接复用。配置在 `public.ecr.aws/docker/library/` 下的 Docker 官方镜像拉取失败时，会立即尝试 Docker Hub 的同名、同版本官方镜像；成功后在本机补上原配置标签，Dockerfile 和交付镜像版本不变。只有临时网络、限流或服务端错误会重试，每个源最多尝试 3 次，轮间等待 5、10 秒；认证错误或不存在的版本不会反复重试。失败时保留各镜像源的原始错误详情。

例如 `public.ecr.aws/docker/library/alpine:3.22.5` 返回 `toomanyrequests: Rate exceeded` 时，脚本会转到 `docker.io/library/alpine:3.22.5`。该策略仅用于明确对应的 Docker 官方镜像；其他仓库沿用配置来源。固定 digest 的引用不会被改成 tag；Docker 无法为备用源补上原 digest 引用时会明确报错，需恢复主源或显式配置同 digest 的备用引用。

首次构建需要联网和足够磁盘：基础镜像、Ghidra、Trivy 数据库、语言依赖及 release 导出的 tar 都占用空间。工具缓存位于 `.cache/tools/`，缺失工具镜像时自动准备；已有工具镜像直接复用。手工制备命令为：

```sh
python script/tools/prepare-tools.py all .cache/tools
```

工具压缩包下载会显示进度条、百分比、已下载/总大小、速度、预计剩余时间和已用时间。交互终端每秒刷新一行，重定向到日志时每 5 秒追加一行；服务器未提供大小且未固定资产大小时只显示已下载量，不估算百分比。连接或读取暂时没有数据时也会持续显示状态，便于区分慢速传输与等待网络。Ghidra 当前固定包约 543 MiB，首次下载耗时取决于到 GitHub Release 的连接速度。

连接/读取沿用 120 秒 socket 超时（不是整个文件的总时限），失败最多尝试 3 次，并打印超时或 HTTP 状态等原因。下载完成后单独提示压缩包完整性和 SHA-256 校验阶段。按 Ctrl+C 中断后可重跑原命令；已完成且校验通过的缓存会复用，未完成文件会从头下载，暂不支持断点续传。更新脚本不会改变已经运行中的下载进程，需要下次执行才生效。

Trivy 漏洞库下载启用工具自身的进度输出，交互终端会为 Docker 分配 TTY；日志重定向时保留非交互运行，不强制分配终端。其超时与上述 Python 文件下载的 socket 超时相互独立：漏洞库下载受 Trivy 默认 5 分钟时限限制，慢网络容易出现 `context deadline exceeded`。构建脚本为漏洞库和 Java 库下载命令分别显式传入 `--timeout 60m`，每个库最多尝试 3 次，失败后依次等待 5、10 秒。每次重试使用新的临时目录，未完成文件从头下载；每个库成功后立即验证并保存，因此 Java 库失败不会丢失已完成的漏洞库。

可在根 `.env` 中设置 `TRIVY_DB_DOWNLOAD_TIMEOUT`（正整数加 `s`、`m` 或 `h`）与 `TRIVY_DB_DOWNLOAD_ATTEMPTS`（1–5）。终端环境变量优先于 `.env`；这些参数只作用于构建机下载，不修改运行时扫描任务时限，也不写入交付配置。例如网络较慢时，从仓库根目录执行：

```powershell
$env:TRIVY_DB_DOWNLOAD_TIMEOUT = "2h"
.\script\build-local\build.ps1
```

下载失败后可直接重新执行原构建命令，不必删除 `.cache/tools`。Ghidra 等已验证工具文件及已完成的 Trivy 数据库会继续复用。完整离线镜像仍要求两个库均准备成功，不会跳过漏洞库以生成缺少数据库的镜像。

Trivy 两个数据库采用不同存储格式：漏洞库 `db/trivy.db` 为 bbolt、元数据版本为 2；Java 库 `java-db/trivy-java.db` 为 SQLite、元数据版本为 1。构建脚本分别校验元数据与对应文件格式，并以只读方式检查 Java 库所需的表和字段，不执行全库扫描。下载后的校验失败会打印具体文件、格式或表结构问题，便于与网络下载失败区分。

工具缓存与镜像会复用漏洞库，不自动刷新。发布新漏洞库时使用新的缓存目录及工具镜像标签，再重建 scanner。离线扫描的漏洞知识范围取决于随包数据库日期。

`images.lock.env` 目前按版本标签、提交号约束依赖，并非全部使用内容 digest。下载文件记录 SHA-256，但记录摘要不等同于验证上游签名。构建期间不要同时修改源码或重建同名镜像。新流程记录 Git revision 与工作树状态；`--skip-build` 导出本机现有镜像，不能据此证明镜像来自当前源码。

## 本地构建和启动

```powershell
# Windows
.\script\build-local\build.ps1
cd local
docker compose up -d --wait
```

```sh
# Linux / macOS
sh script/build-local/build.sh
cd local
docker compose up -d --wait
```

脚本预建所需数据子目录。Linux 上通过已有运行镜像设置 UID/GID 权限，构建本身不启动服务。`local/` 仅供构建机运行；跨机器部署应使用 release，以便导入镜像并初始化目标机权限。

生成目录使用独立 Compose 项目名、`BINARY_DATA_ROOT=./data`，不沿用原个人电脑绝对数据路径。直接执行 Compose 前应进入生成目录；宿主环境同名变量会覆盖 `.env`，需要避免残留设置。包内管理脚本主动加载包配置。

## 制作离线包

```powershell
.\script\build-release\build.ps1
# 已有完整、经过验收的镜像时
.\script\build-release\build.ps1 --skip-build
```

```sh
sh script/build-release/build.sh
# 已有完整、经过验收的镜像时
sh script/build-release/build.sh --skip-build
```

`--skip-build` 适用于两个入口，不下载和拉取镜像；缺失镜像或平台错误即失败。默认构建使用当前工作树，不再强制额外制作旧 demo 源码包。

```text
release/
  docker-compose.yml
  .env
  README.md
  install.sh / install.ps1
  load-images.sh / load-images.ps1
  manage.sh / manage.ps1
  verify.sh / verify.ps1
  images/
    runtime-images.tar
    runtime-images.tar.sha256
  manifests/              # 镜像 ID、平台、构建来源及文件校验清单
  data/                   # 客户安装时产生
```

导出 MySQL、App、scanner、native-decompiler、jvm-decompiler、pyc-decompiler、c-checker、java-checker、python-checker。最终镜像已包含反编译工具、Trivy 主库与 Java 库，不必交付 Go / Node / Maven 构建镜像。

构建先写临时目录，成功后才发布最终目录；目标已存在时拒绝覆盖，避免清空旧 `data/`。生成目录、缓存和测试样例被 Git 与 Docker 构建上下文排除。打包失败不会留下看似可交付的目标目录。

## 客户安装

1. 目标机预装 Docker、Compose，启动 Linux 容器引擎。本包不含 Docker 安装程序，应提前准备。
2. 完整复制 release 目录，包括隐藏文件 `.env`。
3. 按实际地址修改包内 `.env`。远程访问时设置 `APP_BIND_IP=0.0.0.0`、`PUBLIC_BASE_URL=http://服务器地址:端口`，并将相同地址加入 `APP_ALLOWED_ORIGINS`。仅本机访问可保留回环地址。
4. Windows 执行 `.\install.ps1`；Linux 执行 `sudo sh install.sh`；macOS 执行 `sh install.sh`。
5. 用 `.env` 中的 `INITIAL_ADMIN_USERNAME` / `INITIAL_ADMIN_PASSWORD` 登录。

安装先校验不可变交付文件，再导入所有镜像，然后检查配置、平台、目录并执行 `compose up --no-build --pull never --wait`。只有 App 发布端口。

每个新包独立生成数据库、root 和管理员密码，不复制构建机密码。密码只写入包内 `.env`；修改 `.env` 不会重置已初始化的数据库用户或管理员密码。`.env`、`data/` 为可变内容，不参与不可变清单校验，允许客户修改地址。文件校验用于发现传输损坏；来源验证应通过独立可信渠道传递校验清单摘要。

## 日常管理与数据

| 操作 | Shell | PowerShell |
| --- | --- | --- |
| 启动 | `sh manage.sh start` | `.\manage.ps1 start` |
| 检查 | `sh manage.sh doctor` | `.\manage.ps1 doctor` |
| 状态 | `sh manage.sh status` | `.\manage.ps1 status` |
| 日志 | `sh manage.sh logs app` | `.\manage.ps1 logs app` |
| 停止 | `sh manage.sh stop` | `.\manage.ps1 stop` |
| 移除容器并保留数据 | `sh manage.sh down` | `.\manage.ps1 down` |
| 文件校验 | `sh verify.sh` | `.\verify.ps1` |

Linux 离线包由 root 初始化后，日常管理也使用 `sudo sh manage.sh ...`，以读取受保护的 `.env` 和数据标记文件。macOS 与 Windows 可直接使用表中命令。`data/mysql` 与 `data/storage` 是需备份的业务数据，`data/work` 是工作目录。不要在 MySQL 运行时直接复制其目录充当一致性备份。

重新打包前应停止旧包，把旧目录保存在其他位置，再创建新包。迁移既有数据属于升级操作：需要保留旧数据库密码及配置、执行一致性备份并验证版本迁移。本脚本不自动升级或删除旧数据。local 与 release 默认端口相同，同时启动需调整其中一套端口及访问地址。

## 旧脚本迁移

| 原路径（deploy/scripts 下） | 新路径 | 范围 |
| --- | --- | --- |
| release.sh | script/lib/build-images.sh | 按服务构建、镜像导入导出辅助接口 |
| prepare-tools.sh | script/tools/prepare-tools.sh | 原 Unix 工具制备；主流程使用 Python 版 |
| binary.sh、data.sh | script/ops/ | 原根 Compose 与外部绝对路径数据备份恢复 |
| create-deliveries.sh | script/legacy/ | 原 Git HEAD 源码验真 / demo 工作流，需显式传输出目录 |
| smoke、regression | script/tests/ | 原运行验收 |
| 样例生成器 | script/fixtures/ | 外部样例库生成 |

旧 ops 使用根 `.env` 的外部数据路径，不能直接用于新包的 `data/`；新包使用自身 manage 脚本。旧回归脚本默认读取根配置，用于新包验收时应匹配包的项目名、访问地址和账号。依赖外部样例库的脚本要求显式设置 `BINARY_FIXTURE_REPO`，不再默认使用原开发者路径。样例生成器仍保留原有 macOS 等工具依赖，不属于跨平台打包必需步骤。

## 验证范围

`python -m unittest discover -s script/tests -p "test_*.py" -v` 验证打包、工具制备和安装脚本，包括镜像集合、配置、失败清理及旧数据保护。Docker 替身测试不等于真实镜像构建或物理断网验收。正式交付应在完整构建后启动九服务，执行 checker 和上传分析回归，并在目标环境断网完成一次安装。
