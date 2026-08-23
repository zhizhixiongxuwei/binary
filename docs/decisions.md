# 关键决策

1. 新仓库和新数据根均不复制旧系统历史。
2. 根目录只保留 app、checkers、deploy、docs 四个产品边界。
3. 生产固定九个长期容器，无单独前端和代理容器。
4. 单服务器节点提供 HTTP；默认只绑定 localhost，面向单位多用户时由部署人员改为内网地址并用防火墙限制授权网段。多节点 HA 不在第一版范围。
5. `.env` 是提交 Git 的唯一实际部署配置，不使用 Docker secrets。
6. scanner 是三个 checker 的唯一编排者；checker 无 DB、无业务卷。
7. MySQL 队列保留 lease、heartbeat、fencing、幂等和资源槽。
8. 三种源码检查共享 runs/findings 生命周期，语言证据使用有界 JSON。
9. 只在 blob 进入系统和离线包加载边界计算内容摘要。
10. 测试只覆盖并发、安全、路由、三个 checker 合同和一条完整交互式 smoke；发布 smoke 集中在一个脚本中。
