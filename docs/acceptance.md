# 最小验收

发布前必须完成以下场景：

1. 两个不同角色用户通过单位 HTTPS 地址同时登录，权限和审计互不串扰。
2. 上传组合归档后自动完成基础扫描和 Trivy，但没有自动 decompile、check 或 report job。
3. 手动完成 Native 反编译与 C 检查。
4. 手动完成 JAR/APK 反编译，并对 Java 项目执行检查。
5. 手动完成受支持 PYC 反编译与 Python 检查；`bytecode_only` 项目被拒绝检查。
6. 停止任意 checker，只暂停对应语言，scanner 其他能力继续工作。
7. worker 在数据库发布后、finish 前退出，恢复后不重复运行工具。
8. 手动生成 JSON、HTML 和 DOCX 报告并留下审计。
9. 断网重启九个容器后数据仍在，且没有 pull、更新或遥测请求。
10. 完成一次 MySQL 与 storage 的一致性备份恢复。

格式路由使用小型表驱动测试；每个真实工具只保留代表性 smoke，不维护全格式大型 corpus 或逐字节反编译 golden 输出。
