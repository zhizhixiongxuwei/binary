# Java 字节码内部协议

协议 `java-impact-v1` 由 Scanner 调用 java-checker，仅部署在现有内部网络；无新增外部端口。

1. `GET /v1/java-impact/capabilities` 返回引擎版本、目标 Java 范围、运行库模型说明和输入预算。
2. `POST /v1/java-impact/sessions`，JSON 为 `schemaVersion,inputSha256,javaRelease,applicationType,entryPoints,inputs,targets`。`inputs` 每项为 `sha256,logicalPath,size`；第一项是制品，其余是用户显式选择的本地依赖。`targets` 每项为 `occurrenceId,componentPath,ruleId,prefixes`。`componentPath` 与库存路径完全一致，嵌套包用 `!/` 分隔。返回 `sessionId`。
3. `PUT /v1/java-impact/sessions/{id}/inputs/{index}`，原始 `application/octet-stream`，接收端逐字节限制长度并检查 SHA256；拒绝超长、缺失或摘要不符。
4. `POST /v1/java-impact/sessions/{id}/analyze`，返回 `schemaVersion,inputSha256,javaRelease,viewDigest,results,classes,methods,edges,diagnostics`。`results` 按 occurrence ID 索引，每项含 `state,path,diagnostics,complete,engineVersion,inputSha256,viewDigest,ruleId`。HTTP 429 表示共享重任务槽忙，调用者重试；输入不合法为 400，上传不完整/重复分析为 409，会话失效为 404。子进程超限产生明确 `unknown`，不返回“零漏洞”。
5. 无论成功、失败、取消，Scanner 最终调用 `DELETE /v1/java-impact/sessions/{id}`。会话还会在 10 分钟后过期清理，服务关闭时回收子进程。

`asm-cha-v1` 在独立 JVM 中读取指令，不将输入制品加入 JVM classpath，不启动或加载上传的类。子 JVM 上限 512 MiB、180 秒；输入总量 256 MiB，递归 4 层、512 个包、展开 768 MiB、5 万个类、10 万个方法、30 万条已遍历调用边。Spring/WAR 使用公共方法和构造器的保守入口集合；初始化、显式入口、普通调用、多态和可识别 lambda 参与图计算。

Java 8/11/17/21 用于字节码兼容检查和 Multi-Release JAR 有效视图选择。首版运行库只审校了无回调的少量基本操作；其余未解析运行库、依赖、初始化、反射、动态常量/native 等阻止不可达证明。**这些模型不是四套完整 JDK 运行时，也不声称执行环境已被重建。** 缺口出现时，即使未找到目标调用，也返回未知；已有目标路径可作为“模型中可达”的正证据。

Scanner 校验输入、目标、规则及返回结果的对应关系，最终处置还必须通过规则完整性、环境版本、知识摘要、证据有效期、处置 revision 和 run generation 校验。内部结果不直接改变漏洞状态。
