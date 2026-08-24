# 架构边界

## 部署目标

第一版是单单位、单服务器节点、多用户网络访问系统。它不是 localhost-only 桌面程序，也不宣称支持多服务器高可用。

本地 bind mount 数据根和 Compose 内 MySQL 是明确的单节点边界。未来若扩展到多节点，需要把 MySQL 和文件存储替换为外部共享服务。

## 产品流

上传完成后只自动创建基础扫描任务。反编译、源码检查和报告必须由用户分别触发：

    上传 -> 自动格式识别/Trivy
         -> 若为归档，用户手动导入有界文件树
         -> 用户选择文件并手动反编译
         -> 用户选择源码项目并手动检查
         -> 用户选择运行结果并手动生成报告

不存在自动反编译全部文件的后台链路。归档导入支持 ZIP、7Z、RAR、TAR、GZIP、XZ、DEB、RPM 和 ISO 9660，并限制条目数、总展开字节和相对路径；ISO/IMG 按内容识别为 `iso9660`，与压缩包共享一层枚举和批量创建二进制任务的流程。

## 服务职责

- app：Gin API、Vue 静态资源、认证、RBAC、上传、查询、审计和报告。
- scanner：内容识别、归档、Trivy，以及三个 checker 的唯一编排入口。
- native-decompiler：只领取 `native_decompile`，最终镜像包含 Ghidra。
- jvm-decompiler：只领取 `jvm_decompile`，最终镜像包含 Vineflower、CFR 和 JADX。
- pyc-decompiler：只领取 `pyc_decompile`，最终镜像包含 pycdc，不依赖 JVM 工具。
- 三个 checker：内部 HTTP、无数据库、无业务卷、无宿主机端口。

PYC 与 JVM 只是可以共享 Go worker runtime，不能共享工具 capability。`bytecode_only` PYC 项目不能进入 Python checker。

## 任务一致性

所有异步服务共用 MySQL 队列。claim、资源槽和 lease 在同一事务中完成；worker 启动执行后记录 attempt，并通过数据库时间 heartbeat。

每次 claim 增加 fencing token。heartbeat、发布和 finish 都必须同时匹配 job ID、owner、token 和有效租约。旧 worker 的迟到写入必须影响零行。

文件发布使用 run ID 决定的 staging 目录和同文件系统原子 rename。数据库事务和 fencing 决定唯一有效结果，不使用重复哈希代替并发控制。结果数据库事务同时写入 `runs.published_at`；若 worker 在发布后、finish 前退出，lease 回收器直接把 attempt、job 和 run 收敛为成功并释放资源槽，不再次调用工具。数据库提交返回不确定错误时，worker 也会复查发布标记。

checker 连接失败、响应中断、HTTP 408/429/5xx 属于依赖暂不可用。scanner 会结束当前 attempt、释放语言资源槽并延迟重排队；三个 checker job 从创建时刻起使用 12 小时绝对执行/重试期限，同时仍受最大 attempt 数限制。某个 checker 停机不会阻塞 scanner 的归档、Trivy 或其他语言检查。格式错误和 checker 明确返回的 4xx 仍作为永久失败处理。

claim、start、retry 和 finish 的 job、run、attempt 与资源槽关键转换均检查影响行数；lease 回收器锁定过期 job 后，在同一事务修复 attempt、run 与资源槽。静止状态下不允许活跃 job 缺少匹配 owner/fencing 的槽、不允许非活跃 job 占槽，也不允许已发布 run 未收敛为 `complete/succeeded`。

## 哈希边界

- blob 完成持久化时计算一次 SHA-256。
- 离线运行镜像总包在加载前校验一次 SHA-256。
- Docker 镜像使用 OCI digest。
- 密码和 session token 使用安全哈希，这是认证安全，不属于制品重复校验。

项目源码、checker 请求、finding、报告、迁移和 `.env` 不增加应用级摘要字段。
