package com.binaryscan.checker.c;

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

/** The deployed rule registry is the source of IDs, metadata and selection validation. */
final class RuleCatalog {
    private RuleCatalog() {}

    @JsonPropertyOrder({"cwes", "default_enabled", "description", "id", "language", "limitations", "name", "severity"})
    record Rule(String id, String name, String description, List<String> cwes, String severity,
                String language, boolean default_enabled, List<String> limitations) {}

    private static Rule rule(String id, String name, String description, String cwe, String severity, String limit) {
        return new Rule(id, name, description, List.of(cwe.split(",")), severity, "c", true,
            List.of("面向 Ghidra 伪 C 的单文件启发式检查，不提供完整 C/C++ 语义或跨函数污点分析。", limit));
    }

    static final List<Rule> RULES = List.of(
        rule("cwe-242-gets", "危险的 gets 输入函数", "检测无法限制输入长度的 gets 调用。", "CWE-242", "high", "依据调用符号识别；反编译符号缺失可能影响命中。"),
        rule("cwe-120-bounds", "无边界缓冲区操作", "检测 strcpy、strcat、sprintf 等无界操作及未限定宽度的 scanf 字符串转换。", "CWE-120", "high", "不证明目的缓冲区的实际容量和输入长度。"),
        rule("cwe-134-format", "非字面量格式化字符串", "检测格式化函数收到非字面量格式串。", "CWE-134", "high", "非字面量不一定可被外部控制，需要人工确认来源。"),
        rule("cwe-78-command", "非固定字符串命令执行", "检测 system、popen 接收非字面量命令。", "CWE-78", "high", "不验证输入可控性、净化和运行时 shell 行为。"),
        rule("cwe-787-oob-write", "常量数组越界写入", "检测已知局部数组上的常量越界下标写入。", "CWE-787", "high", "依赖可恢复的数组维度和常量下标，不覆盖一般动态边界。"),
        rule("cwe-125-oob-read", "常量数组越界读取", "检测已知局部数组上的常量越界下标读取。", "CWE-125", "high", "依赖可恢复的数组维度和常量下标，不覆盖一般动态边界。"),
        rule("cwe-562-stack-address", "返回局部存储地址", "检测返回局部变量地址或局部数组存储。", "CWE-562", "high", "使用有限的局部声明事实，不跟踪跨函数地址传递。"),
        rule("cwe-590-invalid-free", "释放非堆内存", "检测 free 接收局部存储、字面量或已知非堆指针。", "CWE-590", "high", "仅使用当前文件内能恢复的指针与声明事实。"),
        rule("cwe-761-offset-free", "释放带偏移的指针", "检测 free 接收显式或局部推导的偏移指针。", "CWE-761", "high", "不提供完整指针别名和路径敏感分析。"),
        rule("cwe-369-zero-divisor", "常量除零", "检测除法或取余中的常量零除数。", "CWE-369", "high", "不推导一般变量在运行时是否可能为零。"),
        rule("cwe-377-temp-file", "不安全的临时文件接口", "检测 tmpnam、tempnam、mktemp、tmpfile 等临时文件接口。", "CWE-377", "medium", "是接口使用提示，不证明存在可利用的竞争条件。"),
        rule("cwe-252-unchecked-return", "忽略关键函数返回值", "检测内存、文件、系统及线程等关键接口返回值被直接丢弃。", "CWE-252", "medium", "根据调用语句形态判断，不进行全控制流的返回值使用分析。"),
        rule("cwe-131-size-calculation", "以指针大小申请内存", "检测分配内存时对目标指针变量使用 sizeof。", "CWE-131", "high", "仅覆盖已实现的 sizeof 指针形态，不代表通用整数溢出检测。"),
        rule("cwe-327-328-weak-crypto", "弱加密或消息摘要", "检测可识别的 MD5、SHA-1、DES、RC4 等弱密码学符号。", "CWE-327,CWE-328", "medium", "同一规则可能产生两类 CWE；不能判断算法使用目的和完整参数。"),
        rule("cwe-732-permissions", "授予其他用户写权限", "检测文件或目录权限接口中常量模式包含其他用户写位。", "CWE-732", "medium", "只分析可识别的常量权限模式，不读取系统实际 ACL。")
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
        return Map.of("version", "checker-v1", "language", "c", "catalogVersion", VERSION, "rules", RULES);
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
