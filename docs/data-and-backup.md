# 数据与备份

## 目录

- `mysql`：MySQL 数据目录，必须备份。
- `storage/uploads`：未完成和已接收上传的持久状态。
- `storage/blobs`：不可变输入内容。
- `storage/artifacts`：Trivy 原始结果等运行制品。
- `storage/projects`：三类反编译源码项目。
- `storage/reports`：生成的报告。
- `work`：worker 临时目录，不进入备份。
- `tls`：直接 TLS 模式的运行材料，不属于业务数据。

Docker 日志、镜像、容器元数据和网络信息由 Docker 管理，不在 `binary-data` 保证范围内。

## 一致性备份

第一版采用停写备份：进入维护状态、停止 app 和 worker 写入，备份 MySQL 与整个 `storage`，然后恢复服务。不得只复制 MySQL 或只复制 storage。

恢复演练必须在新的数据根中实际启动，验证数据库引用的 blob、source project 和 report 均存在。`work` 不恢复。

## 删除

业务删除采用数据库标记、文件删除、数据库终态三步。不得先级联删除数据库记录再尝试清理文件。发布后的 project 只允许读取或整体删除，不允许原地修改。
