package com.binaryscan.checker.java;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.security.MessageDigest;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

/** One deployed registry supplies IDs, finding metadata and selectable rules. */
final class RuleCatalog {
    private RuleCatalog() {}

    @JsonPropertyOrder({"cwes", "default_enabled", "description", "id", "language", "limitations", "name", "severity"})
    record Rule(String id, String name, String description, List<String> cwes, String severity,
                String language, boolean default_enabled, List<String> limitations) {
        String cwe() { return cwes.getFirst(); }
        String title() { return name; }
    }

    private static Rule rule(String id, String name, String description, String cwe, String severity, String limit) {
        return new Rule(id, name, description, List.of(cwe), severity, "java", true,
            List.of("面向反编译 Java 的单文件 AST 与局部表达式检查，不提供完整类路径或跨过程污点分析。", limit));
    }

    static final List<Rule> RULES = List.of(
        rule("java-weak-message-digest", "弱消息摘要算法", "检测 MessageDigest 明确选择 MD2、MD4、MD5 或 SHA-1。", "CWE-328", "medium", "限于可解析的常量算法名，未区分安全用途与普通校验。"),
        rule("java-weak-cipher", "弱加密算法或 ECB 模式", "检测 Cipher 选择 DES、RC4 等弱算法或 ECB 模式。", "CWE-327", "medium", "限于可解析的常量算法参数，不验证完整密码协议。"),
        rule("java-legacy-tls", "过时的 TLS 或 SSL 协议", "检测 SSLContext 明确选择旧 SSL、TLS 1.0 或 TLS 1.1。", "CWE-326", "medium", "不检查运行时配置、服务器协商结果或外部配置文件。"),
        rule("java-hardcoded-crypto-key", "硬编码加密密钥", "检测 SecretKeySpec、PBEKeySpec 使用源码中的固定密钥材料。", "CWE-321", "high", "依据局部常量事实，无法确认所有间接密钥来源。"),
        rule("java-trust-all-hostname-verifier", "无条件接受主机名", "检测始终返回 true 的主机名验证实现或 lambda。", "CWE-295", "high", "仅识别已实现的简单无条件接受形态。"),
        rule("java-trust-all-x509-manager", "空的 X.509 信任校验", "检测 X509TrustManager 中不执行校验的信任方法。", "CWE-295", "high", "不推导其他委托校验链路的有效性。"),
        rule("java-xxe-enabled", "启用 XML 外部实体", "检测显式启用外部实体或关闭 DTD 防护的 XML 配置。", "CWE-611", "high", "依赖可识别的配置调用和常量开关，不证明存在外部攻击输入。"),
        rule("java-unsafe-deserialization", "未显式过滤的对象反序列化", "检测 ObjectInputStream 的对象读取。", "CWE-502", "high", "不进行全局对象过滤器、类型白名单或输入可信度证明。"),
        rule("java-sql-injection", "动态拼接 SQL", "检测把非固定值拼接为 SQL 并传给数据库查询接口。", "CWE-89", "high", "使用局部表达式事实，不跟踪完整参数净化或跨函数数据流。"),
        rule("java-command-injection", "动态命令执行", "检测 Runtime.exec 或 ProcessBuilder 使用非编译期常量命令。", "CWE-78", "high", "非固定值不一定可被攻击者控制，需复核调用环境。"),
        rule("java-dynamic-code-execution", "动态脚本或表达式执行", "检测脚本引擎或表达式接口执行动态文本。", "CWE-94", "high", "仅覆盖可识别的脚本和表达式 API 形态。"),
        rule("java-overly-permissive-file", "宽松的文件访问权限", "检测 File 或 POSIX 权限接口授予所有用户宽泛权限。", "CWE-732", "medium", "限于局部类型和常量参数，不读取实际文件系统权限。"),
        rule("java-insecure-cookie", "关闭 Cookie Secure 属性", "检测 Cookie.setSecure(false) 的显式配置。", "CWE-614", "medium", "不检查实际 HTTP 传输、全局 Cookie 策略或其他 Cookie 属性。"),
        rule("java-null-dereference", "空指针解引用", "检测反编译源码中有显式 null 或空值分支证据的解引用。对于可用的原始 JAR 和 CLASS，Scanner 同时执行 SpotBugs 字节码检测。", "CWE-476", "medium", "源码分析跟踪顺序语句和常见条件分支中的局部变量，实例成员须可从当前文件或内置 JDK 类型确认。字节码分析限于指定的空指针解引用模式，结果受类路径和字节码信息影响。")
    ).stream().sorted(Comparator.comparing(Rule::id)).toList();

    static final Set<String> IDS = RULES.stream().map(Rule::id).collect(Collectors.toUnmodifiableSet());
    static final String VERSION = version(RULES);

    static Rule rule(String id) {
        return RULES.stream().filter(rule -> rule.id().equals(id)).findFirst()
            .orElseThrow(() -> new IllegalArgumentException("unknown rule"));
    }

    static String version(List<Rule> rules) {
        try {
            byte[] canonical = new ObjectMapper().writeValueAsBytes(rules.stream().sorted(Comparator.comparing(Rule::id)).toList());
            return "sha256:" + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(canonical));
        } catch (Exception failure) { throw new IllegalStateException("cannot fingerprint rule catalog", failure); }
    }

    static Map<String, Object> catalog() {
        return Map.of("version", "checker-v1", "language", "java", "catalogVersion", VERSION, "rules", RULES);
    }

    static List<String> selection(List<String> ids, String catalogVersion) {
        if (catalogVersion != null && !VERSION.equals(catalogVersion)) throw new IllegalArgumentException("catalog version mismatch");
        if (ids == null) return IDS.stream().sorted().toList();
        if (ids.isEmpty() || ids.size() > 100 || ids.stream().anyMatch(id -> id == null || !IDS.contains(id))) {
            throw new IllegalArgumentException("invalid rule selection");
        }
        return List.copyOf(new TreeSet<>(ids));
    }
}
