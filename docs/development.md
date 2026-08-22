# 开发

## Go

Go module 位于 `app/backend`。五个入口共享 `internal/job`、`internal/storage` 和 worker runtime，但各 decompiler 在编译入口中固定自己的 allowlist。

常用命令：

    cd app/backend
    gofmt -w cmd internal migrations
    go test ./...
    go vet ./...

## Vue

Vue 开发服务器只用于开发：

    cd app/frontend
    npm ci
    npm run dev

Vite 把 `/api` 代理到 `127.0.0.1:8080`。生产前端由 `app/Dockerfile` 构建并嵌入 Go 产品镜像。

需要本机 MySQL 时，用根 Compose 加 `deploy/docker/compose.dev.yml` 覆盖启动 `mysql`。数据库只绑定回环地址的 `DEV_MYSQL_PORT`；开发 app 的 HTTP 端口同样只绑定回环地址。

## Checker

C 和 Java checker 使用 Maven，Python checker只依赖标准库。三者实现 `app/backend/api/checker-v1.yaml`，不得直接访问 MySQL 或业务目录。

测试只放在实现旁边，不创建根 `tests`。同一行为不在 repository、service、API 和 E2E 重复测试。
