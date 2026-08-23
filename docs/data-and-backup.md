# 数据与备份

## 目录

- `mysql`：MySQL 数据目录。备份使用逻辑 dump，不在服务运行时复制这个目录。
- `storage/uploads/<upload-id>/parts`：断点上传会话的分片暂存；完成合并后可清理，会话状态和分片摘要同时记录在 MySQL。
- `storage/blobs`：按 SHA-256 去重的不可变输入内容，包括直接上传文件以及归档一级拆分后物化的成员。
- `storage/artifacts`：Trivy、源码检查器等运行制品，数据库记录其大小、摘要和 schema 版本。
- `storage/projects/{native,jvm,pyc}/<project-id>`：三类反编译源码项目；每个项目包含 `project.json` 清单以及只读源码文件，清单和数据库都保留输入 blob、文件 ID、路径、SHA-256、行数等定位信息。
- `storage/reports`：生成的 JSON、HTML、DOCX 报告；报告中的源码发现保留 source project/file ID 和精确行列范围，可回到任务详情中的 Monaco 编辑器。
- `work`：worker 临时目录，不进入备份。

Docker 日志、镜像、容器元数据和网络信息由 Docker 管理，不在 `binary-data` 保证范围内。

## 一致性备份

第一版采用停写备份。`deploy/scripts/data.sh backup` 会记录原先正在运行的服务，停止 `app`、`scanner` 和三个 decompiler，保持 MySQL 运行并执行 `mysqldump`，随后归档整个 `storage`。成功或失败后都会尽力恢复备份前正在运行的写入服务。checker 没有数据库和业务卷，不属于停写范围。

Linux 上以 root 执行，macOS 上使用当前 Docker Desktop 用户。以下命令以 Linux 为例，macOS 去掉 `sudo`。备份输出必须是仓库和 `BINARY_DATA_ROOT` 之外、尚不存在的目录：

    sudo deploy/scripts/data.sh backup /srv/binaryscan-backup/backup-2026-08-23

备份目录包含：

- `database.sql`：同版本 MySQL 生成的逻辑备份。
- `storage.tar`：完整业务文件存储，不包含 `mysql` 或 `work`。
- `manifest`：版本、MySQL 镜像、schema 版本、关键表行数和两个备份文件的字节数，不包含密码。

数据库 dump 与 storage 必须始终作为同一备份目录保存，不得混用不同时间的文件。工具不计算逐文件哈希；`verify` 检查 manifest、文件字节数、SQL 基线标识、tar 可读性、成员路径及成员类型：

    sudo deploy/scripts/data.sh verify /srv/binaryscan-backup/backup-2026-08-23

备份目录含密码哈希、审计和分析数据，目录权限默认为 `0700`，三个文件默认为 `0600`。只允许从受控介质恢复；结构校验不等同于来源认证。

文件系统原子发布与数据库 fenced 事务之间仍存在极短的跨介质窗口：进程若恰在文件 rename/link 后、数据库提交前退出，可能留下没有数据库引用的 project 或 Trivy artifact。当前版本遵循“不默认丢弃制品”的要求，不自动删除这类文件；备份会原样保留它们。恢复校验保证所有数据库引用都存在，但不会因为额外的未引用文件失败。投产容量巡检应把未引用文件清单作为单独审计项，后续删除必须先人工确认而不是按时间直接清理。

## 恢复演练

恢复演练只接受一个尚不存在或完全为空的新数据根，拒绝当前数据根、Git 仓库、备份目录及其相互嵌套路径。脚本不会覆盖或删除现有业务数据：

    sudo deploy/scripts/data.sh restore-drill \
      /srv/binaryscan-backup/backup-2026-08-23 \
      /srv/binaryscan-restore-2026-08-23 \
      18080

脚本执行以下步骤：

1. 结构化校验备份，并要求 `BINARY_VERSION`、`MYSQL_IMAGE` 和数据库名与当前根 `.env` 一致。
2. 在新数据根中创建标记、空的 `mysql` 和 `work`，只恢复 `storage`。
3. 使用独立 Compose 项目、`127.0.0.1` 临时 HTTP 端口和 `--pull never` 启动 MySQL，确认目标数据库为空后导入 SQL。
4. 比较 schema 版本和关键表行数；逐项检查数据库引用的 blob、Trivy artifact、report 和 source project 是否存在，并比较有记录的文件大小。这里不重新计算内容哈希。
5. 实际启动九个产品服务并等待健康，然后停止并移除演练容器和网络。恢复后的数据根会保留，便于人工检查。

第三个参数为演练使用的宿主机端口，默认 `18080`。该入口只绑定 `127.0.0.1`，不会开放给局域网。演练需要足够资源同时运行九个容器。

生产灾难恢复也必须恢复到新数据根，使用备份 manifest 对应的仓库版本、`.env` 和九镜像离线包。完成数据库与文件引用验证并确认 HTTP 监听地址和防火墙后，才能把正式部署切换到该数据根。初始管理员配置不会覆盖备份数据库中已有管理员的密码。

## 数据根保护

数据脚本会使用 `.binaryscan-data-root` 标记和 `.binaryscan-data-operation` 操作锁。首次备份现有数据根时会在确认 `mysql`、`storage` 目录和路径边界后补建标记。恢复目标的标记由脚本创建。

不要手工删除仍在使用的操作锁。若进程异常退出后留下锁目录，应先确认没有备份或恢复进程、五个写入服务状态稳定，再人工处理。备份目的地不得位于数据根内，否则会造成自包含归档。

## 删除

当前版本尚未开放业务数据删除 API。未来实现删除时必须采用数据库标记、文件删除、数据库终态三步，不得先级联删除数据库记录再尝试清理文件。发布后的 project 只允许读取或整体删除，不允许原地修改。
