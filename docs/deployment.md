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

## 离线交付

制备机负责构建八个产品镜像并连同 MySQL 镜像打包。制备机还必须把 Trivy 离线数据库、Ghidra、Vineflower/CFR/JADX 和 pycdc 固化进相应最终镜像。生产机只执行：

    shasum -a 256 -c binary-runtime.tar.sha256
    docker load -i binary-runtime.tar
    docker compose up --pull never --wait

生产机不得执行 build、pull、npm、Maven、pip 或 Trivy 数据库更新。

当前 worker Dockerfile 使用固定的 Ghidra、JVM tools、pycdc、Trivy 和 archive runtime 基础镜像。这些基础镜像必须先在制备机准备，最终不作为单独运行服务。
