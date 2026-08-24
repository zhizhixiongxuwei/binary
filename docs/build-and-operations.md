# BinaryScan 构建、启动与停止手册

本文覆盖以下日常场景：

1. 修改 Go 后端或 Vue 前端后，只构建 `app` 镜像。
2. 修改 C、Java 或 Python checker 后，构建对应镜像。
3. 镜像准备完成后，通过根目录 `docker-compose.yml` 启动九个服务。
4. 永久清空 `binary-data` 后，以空数据库和空业务目录完成初始化启动。
5. 查看状态、查看日志、暂停、恢复、停止、重新启动和移除容器。

除特别说明外，所有命令都必须从 Git 仓库根目录执行：

```sh
cd /Users/chenzhe/Documents/binary
```

Linux 服务器应替换为实际仓库路径。生产服务器只负责加载预构建最终镜像和启动服务；`build` 命令应在能够取得构建依赖的制备机或开发机执行。

## 一、构建前检查

构建脚本从以下两个文件读取镜像名、版本、平台和基础镜像：

- `.env`：最终产品镜像名、版本和目标平台。
- `deploy/docker/images.lock.env`：Go、Node、Java、Python 等构建基础镜像，以及 Ghidra、JVM 工具、pycdc 和 Trivy 工具镜像。

先确认 Docker 正常：

```sh
docker version
docker compose version
```

当前默认目标平台是 `.env` 中的 `linux/amd64`。如果用户服务器不是 AMD64，必须先修改 `BINARY_PLATFORM`，并为该平台重新构建所有镜像。

## 二、只构建 APP 镜像

`app/Dockerfile` 是多阶段构建：先执行 Vue 3 前端构建，再构建 Go 后端，最后产生同时提供 API 和前端静态资源的 `app` 镜像。因此修改以下任一目录后都执行同一条命令：

- `app/frontend`
- `app/backend` 中只影响 app/API 的代码
- `app/Dockerfile`

构建命令：

```sh
./deploy/scripts/release.sh build-app
```

生成的镜像名由 `.env` 的 `APP_IMAGE` 决定，当前为：

```text
binaryscan/app:0.1.0-dev
```

查看镜像：

```sh
docker image inspect binaryscan/app:0.1.0-dev
```

如果九个服务正在运行，构建完成后使用下面的命令应用新镜像：

```sh
./deploy/scripts/binary.sh up
```

该命令会检查配置，并让 Compose 根据新镜像重建需要更新的容器；不会清空数据库、上传文件、分析结果或报告。

注意：`app/backend` 同时包含 scanner、反编译 worker 共用的 Go 代码。如果修改的是共用任务运行时、数据库访问、协议或 worker 逻辑，只构建 APP 不够，应执行完整构建：

```sh
./deploy/scripts/release.sh build
```

## 三、构建 checker 镜像

### 1. 只构建 C checker

修改 `checkers/c` 后执行：

```sh
./deploy/scripts/release.sh build-c-checker
```

镜像名来自 `.env` 的 `C_CHECKER_IMAGE`。

### 2. 只构建 Java checker

修改 `checkers/java` 后执行：

```sh
./deploy/scripts/release.sh build-java-checker
```

镜像名来自 `.env` 的 `JAVA_CHECKER_IMAGE`。

### 3. 只构建 Python checker

修改 `checkers/python` 后执行：

```sh
./deploy/scripts/release.sh build-python-checker
```

镜像名来自 `.env` 的 `PYTHON_CHECKER_IMAGE`。

### 4. 同时构建三个 checker

```sh
./deploy/scripts/release.sh build-checkers
```

构建完成后，若服务已经运行，统一执行：

```sh
./deploy/scripts/binary.sh up
```

三个 checker 均为无数据库、无业务数据卷的无状态容器。只要 checker 与 scanner 之间的请求/响应协议没有变化，修改 checker 不需要重新构建 scanner；如果协议也发生变化，则应执行完整构建。

## 四、构建全部产品镜像

构建 APP、scanner、三个反编译器和三个 checker：

```sh
./deploy/scripts/release.sh build
```

该命令构建八个产品镜像；MySQL 使用 `.env` 中锁定的官方镜像，不由本仓库构建。

完整构建要求本机已经存在以下四个工具基础镜像：

- Trivy 离线数据库镜像
- Ghidra 运行镜像
- Vineflower/CFR/JADX 工具镜像
- pycdc 工具镜像

如果这些镜像已经被清理，需要在可联网的制备机重新准备。示例：

```sh
./deploy/scripts/prepare-tools.sh all /srv/binaryscan-tool-cache
./deploy/scripts/release.sh build
```

`/srv/binaryscan-tool-cache` 只是制备机下载缓存，不是业务运行数据，也不会挂载到生产容器。

## 五、使用 Compose 启动九个服务

### 推荐启动方式

第一次使用新的空数据目录时先初始化目录：

macOS：

```sh
./deploy/scripts/binary.sh init
```

Linux 服务器：

```sh
sudo ./deploy/scripts/binary.sh init
```

然后检查配置和九个镜像：

```sh
./deploy/scripts/binary.sh doctor
```

Linux 上如果当前账号没有数据目录或 Docker 权限，可以使用：

```sh
sudo ./deploy/scripts/binary.sh doctor
```

启动全部九个服务：

```sh
./deploy/scripts/binary.sh up
```

`up` 会自动再次执行 `doctor`，并使用根目录 `docker-compose.yml` 启动：

1. `mysql`
2. `app`
3. `scanner`
4. `native-decompiler`
5. `jvm-decompiler`
6. `pyc-decompiler`
7. `c-checker`
8. `java-checker`
9. `python-checker`

脚本固定使用 `--pull never`，因此启动生产栈时不会联网拉取镜像。

### 直接执行 docker compose

如果明确需要绕过启动包装脚本，仍应先执行：

```sh
./deploy/scripts/binary.sh doctor
```

然后使用完整 Compose 命令：

```sh
docker compose \
  --project-directory "$PWD" \
  --env-file .env \
  -f docker-compose.yml \
  up -d --pull never --remove-orphans --wait
```

不建议简写成裸 `docker compose up`，因为完整命令明确锁定了仓库根目录、实际 `.env`、生产 YAML 和禁止拉取策略。

### 单位内其他用户访问

默认 `.env` 的 `APP_BIND_IP=127.0.0.1` 只能从服务器本机访问。部署到单位服务器供其他用户使用时，应在启动前修改：

```dotenv
APP_BIND_IP=0.0.0.0
PUBLIC_BASE_URL=http://服务器固定内网IP:8080
APP_ALLOWED_ORIGINS=http://服务器固定内网IP:8080
```

也可以把 `APP_BIND_IP` 设置为服务器自身的固定内网 IP。项目不启用 TLS；只能放在可信单位内网，并通过服务器防火墙限制允许访问 `8080` 的网段。MySQL、worker 和 checker 不应开放宿主机端口。

## 六、清空 binary-data 并初始化启动

这是破坏性操作。它会永久删除 `.env` 中 `BINARY_DATA_ROOT` 指向目录里的全部内容，包括：

- MySQL 数据库和所有用户
- 上传文件和 blob
- 反编译代码和分析制品
- finding、审计、报告和任务记录
- 所有临时工作目录

它不会删除 Git 仓库、Docker 镜像或 Docker 自身日志目录。

当前 `.env` 指向：

```text
/Users/chenzhe/Documents/binary-data
```

macOS 全新初始化启动：

```sh
./deploy/scripts/binary.sh fresh-up --yes
```

Linux 服务器全新初始化启动：

```sh
sudo ./deploy/scripts/binary.sh fresh-up --yes
```

`fresh-up --yes` 会依次执行以下动作：

1. 校验 `BINARY_DATA_ROOT` 是安全的绝对目录，且不与 Git 仓库重叠。
2. 停止并移除当前 Compose 容器。
3. 永久清空数据根目录中的全部内容，包括隐藏文件。
4. 重建 MySQL、storage、projects、reports 和 work 目录及权限。
5. 执行 `doctor`。
6. 启动全部九个服务并等待健康检查通过。

空数据库首次启动后会创建固定管理员：

```text
用户名：admin
密码：admin123456
```

没有 `--yes` 时脚本会直接拒绝执行。日常重启绝对不要使用 `fresh-up`，应使用普通 `up`。

## 七、状态、日志、暂停与停止

### 查看状态

```sh
./deploy/scripts/binary.sh status
```

持续查看全部服务日志：

```sh
./deploy/scripts/binary.sh logs -f
```

只查看 APP 日志：

```sh
./deploy/scripts/binary.sh logs -f app
```

按 `Ctrl+C` 只会退出日志查看，不会停止容器。

### 暂停和恢复

暂停会冻结九个容器中的进程，但不会删除容器或业务数据：

```sh
docker compose --project-directory "$PWD" --env-file .env -f docker-compose.yml pause
```

恢复暂停的容器：

```sh
docker compose --project-directory "$PWD" --env-file .env -f docker-compose.yml unpause
```

暂停期间 Web 页面和任务处理都不可用。不要把暂停当成长期停机方式。

### 停止但保留容器

```sh
docker compose --project-directory "$PWD" --env-file .env -f docker-compose.yml stop
```

重新启动这些已有容器：

```sh
docker compose --project-directory "$PWD" --env-file .env -f docker-compose.yml start
```

`start` 只启动原有容器，不会应用新镜像或新 Compose 配置。代码重新构建或配置修改后，应改用：

```sh
./deploy/scripts/binary.sh up
```

### 停止并移除容器

```sh
./deploy/scripts/binary.sh down
```

该命令移除九个容器和 Compose 网络，但不会删除 `binary-data` 中的数据库及业务文件，也不会删除镜像。以后恢复运行：

```sh
./deploy/scripts/binary.sh up
```

### 普通重启

不修改镜像和配置，仅重启当前容器：

```sh
docker compose --project-directory "$PWD" --env-file .env -f docker-compose.yml restart
```

如果刚完成代码镜像构建，不要使用 `restart`，因为它仍会运行旧容器；应使用 `binary.sh up` 让 Compose 应用新镜像。

## 八、最常用命令速查

| 目的 | 命令 |
| --- | --- |
| 构建 APP | `./deploy/scripts/release.sh build-app` |
| 构建 C checker | `./deploy/scripts/release.sh build-c-checker` |
| 构建 Java checker | `./deploy/scripts/release.sh build-java-checker` |
| 构建 Python checker | `./deploy/scripts/release.sh build-python-checker` |
| 构建三个 checker | `./deploy/scripts/release.sh build-checkers` |
| 构建全部产品镜像 | `./deploy/scripts/release.sh build` |
| 初始化空目录（不删除已有数据） | `./deploy/scripts/binary.sh init` |
| 配置检查 | `./deploy/scripts/binary.sh doctor` |
| 启动或应用新镜像 | `./deploy/scripts/binary.sh up` |
| 查看状态 | `./deploy/scripts/binary.sh status` |
| 查看日志 | `./deploy/scripts/binary.sh logs -f` |
| 暂停 | `docker compose --project-directory "$PWD" --env-file .env -f docker-compose.yml pause` |
| 恢复暂停 | `docker compose --project-directory "$PWD" --env-file .env -f docker-compose.yml unpause` |
| 停止并保留容器 | `docker compose --project-directory "$PWD" --env-file .env -f docker-compose.yml stop` |
| 停止并移除容器、保留业务数据 | `./deploy/scripts/binary.sh down` |
| 永久清空业务数据后初始化启动 | `./deploy/scripts/binary.sh fresh-up --yes` |
