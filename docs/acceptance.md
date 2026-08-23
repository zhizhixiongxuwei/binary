# 最小验收

发布前必须完成以下场景：

1. administrator、operator 和 reader 通过单位 HTTP 地址同时登录，权限和审计互不串扰；入口只能位于受控内网，防火墙只放行授权网段。
2. 上传组合归档后自动完成格式识别和 Trivy；用户手动导入归档文件树，且没有自动 decompile、check 或 report job。
3. 手动完成 Native 反编译与 C 检查。
4. 手动完成 JAR 或 APK 反编译，并对 Java 项目执行检查；正式文件矩阵还应各保留一个 DEX/APK 样本。
5. 手动完成受支持 PYC 反编译与 Python 检查；`bytecode_only` 项目被拒绝检查。
6. 停止任意 checker，只暂停对应语言，scanner 其他能力继续工作。
7. worker 在数据库发布后、finish 前退出，恢复后不重复运行工具。
8. 手动生成 JSON、HTML 和 Word 报告并留下审计；报告只包含用户显式选择的终态运行。
9. 断网重启九个容器后数据仍在，且没有 pull、更新或遥测请求。
10. 完成一次 MySQL 与 storage 的一致性备份恢复。

格式路由使用小型表驱动测试；每个真实工具只保留代表性 smoke，不维护全格式大型 corpus 或逐字节反编译 golden 输出。

## 制备机验收记录（2026-08-22）

本阶段已完成以下可重复检查：

- 构建并检查 Ghidra 12.1.3、Vineflower 1.12.0 / CFR 0.152 / JADX 1.5.6、pycdc `b428976` 和 Trivy 0.74.0 离线工具镜像；五个 Go 产品进程使用 Go 1.26.7 构建。
- 构建 app、scanner、三个 decompiler 和三个 checker 产品镜像，目标平台均为 `linux/amd64`。
- 用 x86-64 ELF 验证 Ghidra headless，成功产生类 C 源文件；用 Java 21 class 验证 Vineflower；用 Python 3.9 PYC 验证 pycdc。
- 用最终 scanner 镜像在禁止数据库更新的参数下完成仓库依赖扫描，确认内置普通数据库和 Java 数据库可读。
- 对三个最终 checker 镜像分别执行健康检查和 `checker-v1` 请求，命中 `C001`、`JAVA001`、`PY001` 代表性规则。
- 用最终 scanner 镜像对八个产品镜像逐一做离线漏洞扫描，全部镜像均无数据库已给出修复版本的条目。Go 产品仍包含数据库未给出修复版本的 `GO-2026-5932`，Java/操作系统基础层也保留若干无修复版本条目；未添加忽略规则。Python checker 删除了运行时不需要的 pip/ensurepip，Ghidra runtime 删除了模块清单明确排除且 headless 流程不加载的 GhidraServer YAJSW 包装器，收口后再次通过真实检查与反编译。
- 在仓库外生成 2.8 GB 的九镜像离线归档，从不同工作目录完成 SHA-256 校验，并由该归档成功重新加载全部九个生产镜像。

以上记录只证明制备机镜像和代表性工具链可用，不替代本页第 1—10 项目标生产环境验收。

## 隔离产品验收记录（2026-08-23）

以下业务与故障恢复记录来自移除 TLS 之前的最终镜像；其中证书相关结论仅是历史记录，不再代表当前入口。当前 HTTP 入口的回归记录见下一节。

在仓库外数据根 `/Users/chenzhe/Documents/binary-data/acceptance-phase4`、回环端口 `18443` 和短期验收证书上，用最终 `linux/amd64` 镜像完成了以下检查：

- 九个服务全部健康，app direct TLS 的证书链和主机名由客户端 CA 校验通过；只有 app 发布宿主机端口，三个 checker 仍无数据库变量、业务卷和宿主机端口。
- administrator、operator、reader 三个角色同时建立独立 session。reader 查询成功但上传得到 403；operator 完成整条分析流；管理员自降级被拒绝，停用 reader 后其 session 立即失效。登录、用户换密和管理员重置使用同一用户行锁串行化，避免旧密码并发登录在会话撤销后写入新 session。用户变更、登录、任务、run 和报告动作均可从管理审计接口读取，认证材料未出现在响应中。
- 上传组合 ZIP 后只有 `scan` 和 `trivy_scan` 两个自动运行。手动导入后识别 ELF、JAR 和 Python 3.9 PYC，再分别由 Ghidra、Vineflower 和 pycdc 成功生成 C、Java、Python project。
- 三个源码检查均由用户手动触发，代表性危险调用分别命中 `C005`、`JAVA002` 和 `PY001`。同一手动请求重放返回原 run ID，没有创建重复 run。
- 停止 `python-checker` 后 Python check 在第一次 attempt 失败时释放槽并回到延迟队列；同时 C、Java check 正常完成。scanner 也能在 Python checker 保持停止时独立冷启动并通过健康检查；恢复 checker 后原 Python run 成功收敛。另注入一个创建时间已超过 13 小时的 checker job，确认只执行 1 次即失败，没有越过 12 小时绝对期限继续重排队。
- 对一个已发布 C check 注入“run/job/attempt 仍 running 且 lease 已过期”的崩溃状态。回收后 attempt 数仍为 1，run/job 为 `complete/succeeded`，资源槽释放，4 个 finding 和 19 个任务事件均未增加。
- 对一个未发布、attempt 已耗尽的 scan job 注入过期 lease。回收后 task/run/job 同时变为 `failed`，attempt 变为 `lease_lost`、错误码为 `attempts_exhausted`，资源槽释放。
- 生成并下载 JSON、HTML 报告，两份报告只包含显式选择的 9 个终态 run；JSON schema 为 `binaryscan-report-v1`。九容器完整停止后使用 `--pull never` 启动，任务与报告仍可读取。最终 `binary-runtime-0.1.0-dev-amd64-phase4-final.tar`（2.8 GB）校验通过，并由该包重新加载全部九镜像。
- 实际备份位于 `/Users/chenzhe/Documents/binary-backup-phase4`。恢复脚本把 MySQL dump 与 storage 导入全新的数据根 `/Users/chenzhe/Documents/binary-restore-phase4-final9`，11 组 schema/业务计数和 4 个数据库到文件引用一致；即使调用环境故意设置其他 `COMPOSE_FILE`，脚本仍固定使用正式根 Compose。最终九镜像健康后自动移除演练容器，`work` 和 `tls` 未被恢复。
- 最终队列静止后，活跃 job/slot、非活跃占槽、running attempt、已发布未完成和孤立 running attempt 五类一致性查询均为零。
- Vue 产品构建和本机 HTTP 验收页的 DOM/视觉检查通过；direct TLS 页面未在浏览器中绕过自签名证书警告，TLS 功能由受信 CA 的命令行客户端验证。
- 单一 `deploy/scripts/smoke.sh` 已补齐可重复的 topology、三个 `checker-v1` contract 和 live 模式。live 模式再次验证 PYC 上传后仅自动产生 scan/Trivy，随后手动 pycdc、Python check 命中 `PY001`，并下载包含 4 个显式 run 的 JSON 报告；临时验收账号结束后已停用且无残留 session。

## 纯 HTTP localhost 回归（2026-08-23）

- 根 `.env` 使用 `http://localhost:8080`，app 只发布 `127.0.0.1:8080`；Compose 不再挂载证书目录或注入 TLS/可信代理变量。
- 重新构建 app 产品镜像后，正式 `binary` 项目的九个长期容器全部健康；首页、`healthz` 和 `readyz` 均通过 HTTP 访问。
- topology 和三个真实 `checker-v1` contract 通过。完整 live smoke 任务 `91debe32-b5b3-4acc-8764-4d573eeb22b6` 完成 PYC 上传、scan/Trivy、pycdc、Python check 与报告 `92519a66-06d4-44ba-a61c-5e5bec387188` 下载。
- 临时 HTTP smoke 账号已停用且无 session；活跃 job、运行中 attempt 和占用 slot 均为零。
- 旧备份恢复到新的 `/Users/chenzhe/Documents/binary-restore-http-final`，数据库计数和 4 个数据库到 storage 引用一致；恢复根没有 `tls` 目录，九服务健康后演练容器和网络已全部移除。调用环境中的其他 `COMPOSE_FILE` 未改变正式拓扑。
- 新九镜像离线包为 `binary-runtime-0.1.0-dev-amd64-http.tar`（2.8 GB），SHA-256 为 `5df7f3034c13f90043fb3812366675f84b84f60e76b5de481b71b67608508434`。旧 direct-TLS 包只保留为历史证据，不得用于当前部署。

这次验收仍不替代目标单位现场检查。投产门槛剩余：实际 HTTP 访问地址、授权网段防火墙、按实际并发与大文件进行容量测试、物理断网后的 `--pull never` 再启动，以及 PE/Mach-O/DEX/APK 等单位实际文件矩阵。验收测试账号不得复制到生产环境。
