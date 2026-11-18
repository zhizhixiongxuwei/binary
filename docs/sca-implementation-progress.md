# SBOM / Java SCA 实施与验收记录

用户已批准实施计划，并于 2026-11-17 要求按 B0 → B4 完整实现。**五个阶段现已完成，代码、接口文档、验收证据及离线交付包已生成；未部署客户生产环境。**

依据：[需求分析](requirements-sbom-java-vulnerability-analysis.md)、[已批准修改计划](implementation-plan-sbom-java-vulnerability-analysis.md)。

## B0：技术基线

- 客户未提供样本，使用可再生的 SPDX 2.3、CycloneDX 1.4–1.6 JSON/XML、SWID 2015 清单，以及真实 Commons Text 1.9 / Commons Lang 3.11 依赖构成的普通/Boot/WAR 字节码样本。生成器：`script/fixtures/sca_samples.py`；生成文件和 SHA256 清单位于忽略目录 `test-fixtures/sca`。
- 当前离线 Trivy 0.74.0：SPDX JSON、CycloneDX JSON 在 `--network none` 下可检出 CVE-2022-42889。直接 fs 扫描这些 JAR/依赖目录产生零组件，故采用“产品归一化组件库存 → CycloneDX → Trivy SBOM”，不得以 fs 零结果作为扫描成功证据。
- 调用图实现采用现有 Spring ASM 的保守 CHA 模型，不额外引入 SootUp 及其运行库依赖。独立探针验证 main 中直接调用、未调用方法与反射指令可区分。完整性取决于实际解析依赖、入口和动态缺口；未覆盖 JDK 行为不能用于证明不可达。SootUp 可作为未来扩大模型的候选。
- JSON 校验器固定 `github.com/santhosh-tekuri/jsonschema/v6 v6.0.2`，schema 全部嵌入且拒绝远端加载。XML 采用离线官方 XSD 与 scanner 镜像内的 libxml2 xmllint；文档输入拒绝 DTD/实体，schema 引用固定本地。
- schema 来源和变换摘要保存在 `internal/sbom/schemas/manifest.json`；构建准备脚本不用于扫描时下载。SWID 必须取 NIST 所链接的 ISO `2015-current` 地址；旧 `/2015/` 地址实际返回 2014-DIS namespace，已避免错误复用。
- 首批方法规则来源：[Apache Commons Text 官方安全公告](https://commons.apache.org/proper/commons-text/security.html)。未审校的漏洞保留组件命中和未知状态；不能从公告文字自动生成“不受影响”的证明。
- 基线前端：44 文件、233 测试通过。Windows Go 因既有 Linux Flock 无法原生编译，改用 Linux Go 容器；宿主 Java 17 与旧 Maven 镜像配置不可用，改用已有 JDK 21 Maven 容器和任务独立 settings。

## 批次状态

| 批次 | 状态 |
| --- | --- |
| B0 | 已冻结 schema、引擎、规则及资源预算；真实离线样本探针通过 |
| B1 | 已实现迁移 14–18、标准解析、统一库存、分页与接口契约 |
| B2 | 已实现 JAR/Boot/WAR 库存、真实离线 Trivy 匹配、环境与策略不可变版本、规则包 |
| B3 | 已实现三维分析、证据门槛、自动忽略、人工覆盖、版本隔离及到期重评 |
| B4 | 页面、报告、九镜像离线包及最终验收已完成 |

## 最终实现设计

- `sbom`、`java_sca` 为独立分析模式。同一 JAR 可继续创建原二进制反编译任务，组件漏洞分析不混入源码缺陷检查。
- SPDX 2.3 JSON/TagValue 使用官方 JSON schema 和 SPDX 官方 tools-golang 解析器。SPDX 2.3.1 维护版本仍使用 `SPDX-2.3` 文档版本值，官方版本示例纳入兼容测试；参见 [官方文档创建字段](https://spdx.github.io/spdx-spec/v2.3.1/document-creation-information/) 与 [版本说明](https://spdx.github.io/spdx-spec/v2.3.1/conformance/)。
- 官方完整 TagValue 样本中的独立 snippet 段增加了顺序兼容适配；字段仍由上游解析器解析，再展开为标准 JSON 并做 schema 校验，原文保持不变。
- CycloneDX 1.4/1.5/1.6 JSON/XML；SWID 2015 单标签和显式本地标签集合。集合成员固定已解析库存摘要，支持 `swid:tagId` 与显式成员间的相对路径，不跟随远端链接。SWID `Link rel=component` 不会被误用为标签自身身份；不能直接识别的 tagId 可由操作员显式映射 PURL，映射声明保留在来源记录。
- 各原文和原始 Trivy 制品保留。组件身份缺失、缺版本、冲突、shaded 多坐标、无法映射的扫描命中等均显式诊断；无法映射的原始漏洞仍作为 unresolved 实例展示。
- 首批影响规则只有 **CVE-2022-42889** 的保守插值 API 目标集合，以及 **CVE-2021-45105** 的已审校环境/攻击前提。后者依据 [Apache 官方公告](https://logging.apache.org/security.html#CVE-2021-45105)。其余可靠匹配漏洞照常报告，影响结论保持未知。
- main、自定义入口、应用初始化、普通调用、多态、可识别 lambda 进入调用图；Spring/WAR 使用公共方法和构造器的保守入口集合。Java 8/11/17/21 分别选择 Multi-Release 有效字节码并绑定视图摘要。**首版没有完整重建四套 JDK 运行库**，未审校运行库、缺失依赖、动态行为、反射/native、资源上限均阻止不可达证明，详见 [内部协议与引擎边界](java-impact-v1.md)。
- 三维结论分别保存可达性、漏洞环境适用性、攻击条件，并保留原始 CVSS 与来源；“可达”不等于“已可利用”，“环境兼容性”不表示升级兼容性测试。
- 默认仅建议；显式启用自动策略后，只有完整代码排除或必要条件的可靠排除才能置为已忽略。未验证声明、低分或“内网”本身不能自动忽略。事实及策略到期、环境版本、知识摘要变化都会使旧结论失效；查询立即按失效状态显示，周期检查器有界重评。
- 同一漏洞按任务、制品、组件身份及实例路径建立稳定 occurrence。环境分别处置，只有所有已有目标范围都有效忽略才汇总为已忽略。人工恢复要求保留期限，晚到 Worker 不能覆盖人工处置或新一代分析；变更、排队及处置进入不可变历史和审计。
- 新 API 复用 session/CSRF 与 administrator/operator/reader 权限。契约见 [SCA OpenAPI](../app/backend/api/sca-v1.yaml)，主 OpenAPI 已关联。新模式报告为 `binaryscan-report-v5`，支持 JSON/HTML/DOCX，固定原始命中、相关分析历史、环境/策略与生成时有效处置，旧报告保持原 schema。
- 沿用九服务部署，不增加独立重分析服务。Java 使用独立限时子 JVM，与原 Java 重任务共享槽；上传字节码不执行。scanner 新增 xmllint 与 impact 槽预算，schema/规则已嵌入，运行时不隐式下载。

## 可复现验证与交付

使用独立、带 `binaryscan.sca-test=true` 标签的 MySQL/Scanner/Java/App 容器；未修改现有部署 `.env`，未启动生产 Compose。主验收 App 仅绑定本机 18084；交付数据库兼容验收使用 18085；分析服务位于 Docker `--internal` 网络。测试账号为 `sca-review` / `SCA-review-2026!`，仅属于这些隔离验收环境，与交付包初始账号独立。

```powershell
python script/fixtures/sca_samples.py
python script/tests/sca-migrations.py
python script/tests/sca-integration.py setup
python script/tests/sca-integration.py verify
python script/tests/sca-release.py
```

- Go：使用 Linux `golang:1.26.7-bookworm` 执行 `go test ./...`，包含真实 MySQL 的并发处置/人工覆盖测试；Windows 原生受既有 Flock 实现限制。
- Java：JDK 21 Maven `mvn test`，17 个测试类、107 项测试通过；包含九种真实档案正/反/反射样本，以及 Java 8/11/17/21 Multi-Release 选择与摘要测试。
- 前端：45 个测试文件、235 个测试通过；生产构建通过。浏览器检查覆盖新工作台入口、任务类型、进度、环境设置及证据展示。
- 数据库：MySQL **8.0.46**（交付镜像实际版本）与 **9.7.1** 均完成新建库、14–18 迁移重复执行及真实链路验收；Linux Go 全量测试也在 MySQL 8.0.46 上通过。
- 最终镜像真实离线 HTTP 验收：**22 组场景全部通过，并在上述两个数据库版本上各完整执行**。包括九种基础清单、两种 SPDX 2.3.1 官方完整样本、SWID 显式集合及本地关系、九种普通/Boot/WAR 可达/不可达/反射样本、已审校条件规则。另验证人工恢复、JSON/HTML/DOCX、证据到期立即恢复待处置及自动重评、环境版本冲突、多环境汇总、CSRF、只读账号拒绝写操作、原始 CVSS 保持不变。
- 交付脚本既有回归：77 项 Python 测试通过。实际离线归档及交付文件使用 `verify.ps1 package` 校验通过；镜像 tar 为 **6,663,440,896 字节（约 6.66 GB）**。
- 管理端实际探测：`sbom-normalizer`、`java-impact`、`impact-rules` 均为 available/fresh。Trivy 0.74.0 随包漏洞库及 Java 库的实际快照更新时间均为 **2026-10-23**；这是仓库既有离线库快照，不宣称是实时最新数据，后续更新沿用原离线库流程。
- 生成输入与 SHA256：`test-fixtures/sca/manifest.json`；HTTP 验收证据：`.cache/sca/acceptance.json`（MySQL 8）、`.cache/sca/acceptance-mysql9.json`。页面截图：`.cache/sca/ui-acceptance.jpg`。生成输入与容器数据不提交 Git。
- 离线交付生成器从当前工作区重新构建八个产品镜像并搭配锁定 MySQL 镜像，输出 `.cache/sca/delivery-source/release/`。不覆盖既有 `local/`、`release/`、产品镜像旧标签或 `.env`。包内镜像清单、tar 摘要和交付文件摘要用于验收；验证脚本与原部署保持一致。
- 最终源码输入摘要：`c474191632f05efb84ef47eeac37d869369a5c70e6074caea93afe4a991dc08f`，逐文件摘要位于包内 `manifests/source-files.sha256`；构建期间输入发生变化会拒绝封装。代码以工作区差异保留，未自动创建 Git 提交。

上述结果验证了约定首版链路，不代表全部框架、全部 JDK 方法及全部 CVE 均已建立确定性分析规则。支持的文本清单按 UTF-8 输入验证，其他标准版本/序列化不会静默当作已支持版本。

本机主验收环境保留在 `http://127.0.0.1:18084` 供查看；MySQL 8 兼容验收环境完成后停止以释放资源，数据和验收证据仍保留。离线包还包含 `docs/`、`evidence/`、`fixtures/sca/`，可直接用包内真实样本进行页面验收。所有新增数据均属于隔离测试环境。

## 规则维护与升级

内置规则之外可安装经过审校的离线 JSON 规则包。App 与 Scanner 必须同时设置相同的 `BINARY_IMPACT_RULE_BUNDLE` 文件与 `BINARY_IMPACT_RULE_SHA256`，通过只读挂载或制作定制镜像分发；无需在线编辑器。源公告、目标集合是否覆盖完整、每个利用分支的必要条件和正反测试都必须随规则评审。旧知识摘要的自动忽略立即视为失效，再由检查器重评。错误或摘要不符的包会报告不可用。

生产升级前备份数据库和 storage，更新所有匹配版本的服务，再检查 `/admin/system` 的新能力。旧版本不认识新增枚举，降级采用验证过的前向修复或恢复升级前备份。交付包尚未在客户生产环境安装；客户实际框架、私有依赖、混淆包及声明证据仍需结合真实样本验收。
