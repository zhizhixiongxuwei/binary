# 最小验收

发布前必须完成以下场景：

1. 两个不同角色用户通过单位 HTTPS 地址同时登录，权限和审计互不串扰。
2. 上传组合归档后自动完成格式识别和 Trivy；用户手动导入归档文件树，且没有自动 decompile、check 或 report job。
3. 手动完成 Native 反编译与 C 检查。
4. 手动完成 JAR/APK 反编译，并对 Java 项目执行检查。
5. 手动完成受支持 PYC 反编译与 Python 检查；`bytecode_only` 项目被拒绝检查。
6. 停止任意 checker，只暂停对应语言，scanner 其他能力继续工作。
7. worker 在数据库发布后、finish 前退出，恢复后不重复运行工具。
8. 手动生成 JSON 和 HTML 报告并留下审计；报告只包含用户显式选择的终态运行。
9. 断网重启九个容器后数据仍在，且没有 pull、更新或遥测请求。
10. 完成一次 MySQL 与 storage 的一致性备份恢复。

格式路由使用小型表驱动测试；每个真实工具只保留代表性 smoke，不维护全格式大型 corpus 或逐字节反编译 golden 输出。

## 制备机验收记录（2026-08-22）

本阶段已完成以下可重复检查：

- 构建并检查 Ghidra 12.1.2、Vineflower 1.12.0 / CFR 0.152 / JADX 1.5.6、pycdc `b428976` 和 Trivy 0.72.0 离线工具镜像。
- 构建 app、scanner、三个 decompiler 和三个 checker 产品镜像，目标平台均为 `linux/amd64`。
- 用 x86-64 ELF 验证 Ghidra headless，成功产生类 C 源文件；用 Java 21 class 验证 Vineflower；用 Python 3.9 PYC 验证 pycdc。
- 用最终 scanner 镜像在禁止数据库更新的参数下完成仓库依赖扫描，确认内置普通数据库和 Java 数据库可读。
- 对三个最终 checker 镜像分别执行健康检查和 `checker-v1` 请求，命中 `C001`、`JAVA001`、`PY001` 代表性规则。
- 根据离线扫描结果升级可修复的 Go 依赖后重新扫描；当前只剩 `GO-2026-5932`，Trivy 数据库将其标记为 `UNKNOWN` 且未提供修复版本，未添加忽略规则。
- 在仓库外生成 2.8 GB 的九镜像离线归档，从不同工作目录完成 SHA-256 校验，并由该归档成功重新加载全部九个生产镜像。

以上记录只证明制备机镜像和代表性工具链可用，不替代本页第 1—10 项目标生产环境验收。
