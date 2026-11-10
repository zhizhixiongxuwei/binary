package com.binaryscan.checker.java;

import com.binaryscan.checker.java.RuleCatalog.Rule;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.ImportDeclaration;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.ConstructorDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.BooleanLiteralExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.LambdaExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.stmt.BlockStmt;
import com.github.javaparser.ast.stmt.ReturnStmt;
import com.github.javaparser.ast.stmt.Statement;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * 基于 JavaParser AST 的 Java 静态规则引擎。
 *
 * <p>Vineflower/CFR/JADX 产生的是可读源码而非原始工程，类型解析所需的依赖通常不存在。
 * 因此本引擎采用“语法树 + 局部表达式事实”策略：先枚举调用与对象创建节点，再由
 * {@link ExpressionFacts} 判断常量、动态拼接、变量最近定义和局部声明类型。这样既能覆盖常见
 * 密码学、XXE、反序列化、SQL/命令注入和权限问题，又不会假装拥有完整类路径语义。</p>
 */
@Component
final class JavaAnalyzer {
    private static final Rule WEAK_DIGEST = RuleCatalog.rule("java-weak-message-digest");
    private static final Rule WEAK_CIPHER = RuleCatalog.rule("java-weak-cipher");
    private static final Rule LEGACY_TLS = RuleCatalog.rule("java-legacy-tls");
    private static final Rule HARDCODED_KEY = RuleCatalog.rule("java-hardcoded-crypto-key");
    private static final Rule TRUST_HOSTNAME = RuleCatalog.rule("java-trust-all-hostname-verifier");
    private static final Rule TRUST_X509 = RuleCatalog.rule("java-trust-all-x509-manager");
    private static final Rule XXE = RuleCatalog.rule("java-xxe-enabled");
    private static final Rule DESERIALIZATION = RuleCatalog.rule("java-unsafe-deserialization");
    private static final Rule SQL_INJECTION = RuleCatalog.rule("java-sql-injection");
    private static final Rule COMMAND_INJECTION = RuleCatalog.rule("java-command-injection");
    private static final Rule DYNAMIC_CODE = RuleCatalog.rule("java-dynamic-code-execution");
    private static final Rule BROAD_PERMISSION = RuleCatalog.rule("java-overly-permissive-file");
    private static final Rule INSECURE_COOKIE = RuleCatalog.rule("java-insecure-cookie");
    private static final Rule NULL_DEREFERENCE = RuleCatalog.rule("java-null-dereference");

    static final Set<String> RULE_IDS = RuleCatalog.IDS;

    private static final Pattern SQL_TEXT = Pattern.compile(
        "(?is)\\b(select|insert|update|delete|merge|replace|call)\\b.*");
    private static final Set<String> SQL_METHODS = Set.of(
        "execute", "executeQuery", "executeUpdate", "executeLargeUpdate", "addBatch",
        "prepareStatement", "prepareCall", "createNativeQuery", "createQuery");
    private static final Set<String> EXTERNAL_ENTITY_FEATURES = Set.of(
        "http://xml.org/sax/features/external-general-entities",
        "http://xml.org/sax/features/external-parameter-entities",
        "http://apache.org/xml/features/nonvalidating/load-external-dtd");
    private static final Set<String> DISABLE_DTD_FEATURES = Set.of(
        "http://apache.org/xml/features/disallow-doctype-decl");

    Analysis analyze(Models.SourceFile file) {
        return analyze(file, RULE_IDS);
    }

    Analysis analyze(Models.SourceFile file, Set<String> enabledRules) {
        if (!RULE_IDS.containsAll(enabledRules)) throw new IllegalArgumentException("unknown rule");
        if (enabledRules.isEmpty()) return new Analysis(List.of(), List.of());
        var findings = new ArrayList<Models.Finding>();
        var diagnostics = new ArrayList<String>();
        try {
            CompilationUnit unit = StaticJavaParser.parse(file.content());
            Emitter emitter = new Emitter(file.path(), findings, enabledRules);
            // 固定遍历顺序和最终排序，使相同源码在不同运行中生成稳定、可复核的 Finding。
            for (MethodCallExpr call : sorted(unit.findAll(MethodCallExpr.class))) {
                if (emitter.enabled(WEAK_DIGEST) || emitter.enabled(WEAK_CIPHER) || emitter.enabled(LEGACY_TLS)) evaluateCrypto(unit, call, emitter);
                if (emitter.enabled(XXE)) evaluateXxe(call, emitter);
                if (emitter.enabled(DESERIALIZATION)) evaluateDeserialization(call, emitter);
                if (emitter.enabled(SQL_INJECTION)) evaluateSql(call, emitter);
                if (emitter.enabled(COMMAND_INJECTION)) evaluateCommand(call, emitter);
                if (emitter.enabled(DYNAMIC_CODE)) evaluateDynamicCode(call, emitter);
                if (emitter.enabled(BROAD_PERMISSION)) evaluatePermissions(call, emitter);
                if (emitter.enabled(INSECURE_COOKIE)) evaluateCookie(call, emitter);
                if (emitter.enabled(TRUST_HOSTNAME)) evaluateHostnameCall(call, emitter);
            }
            for (ObjectCreationExpr creation : sorted(unit.findAll(ObjectCreationExpr.class))) {
                if (emitter.enabled(HARDCODED_KEY)) evaluateHardcodedKey(creation, emitter);
                if (emitter.enabled(COMMAND_INJECTION)) evaluateProcessBuilder(creation, emitter);
            }
            if (emitter.enabled(TRUST_HOSTNAME)) evaluateHostnameImplementations(unit, emitter);
            if (emitter.enabled(TRUST_X509)) evaluateTrustManagers(unit, emitter);
            if (emitter.enabled(NULL_DEREFERENCE)) {
                NullDereferenceAnalyzer.analyze(unit, finding -> emitter.emit(NULL_DEREFERENCE, finding.node(), finding.message(),
                    Map.of("ruleFamily", NULL_DEREFERENCE.id(), "dereferenceKind", finding.kind(),
                        "dereferenceMember", finding.member(), "uniqueDereferenceOnLine", finding.uniqueOnLine())));
            }
            findings.sort(Comparator.comparingInt(Models.Finding::line)
                .thenComparingInt(Models.Finding::column).thenComparing(Models.Finding::ruleId));
        } catch (RuntimeException exception) {
            // 单个反编译文件可能因缺失语句或反编译器占位符无法解析，不应拖垮整个项目。
            diagnostics.add(file.path() + ": parser rejected decompiled source");
        }
        return new Analysis(findings, diagnostics);
    }

    private static void evaluateCrypto(CompilationUnit unit, MethodCallExpr call, Emitter emitter) {
        if (!"getInstance".equals(call.getNameAsString()) || call.getArguments().isEmpty()) return;
        Optional<String> configured = ExpressionFacts.constantString(call.getArgument(0));
        if (configured.isEmpty() || configured.get().length() > 128) return;
        String raw = configured.get().trim();
        String algorithm = raw.toUpperCase(Locale.ROOT).replace("-", "");
        if (emitter.enabled(WEAK_DIGEST) && isStaticTypeCall(unit, call, "MessageDigest", "java.security.MessageDigest")
            && Set.of("MD2", "MD4", "MD5", "SHA1").contains(algorithm)) {
            emitter.emit(WEAK_DIGEST, call, "MessageDigest selects the weak " + raw + " algorithm");
        }
        if (emitter.enabled(WEAK_CIPHER) && isStaticTypeCall(unit, call, "Cipher", "javax.crypto.Cipher") && weakCipher(algorithm)) {
            emitter.emit(WEAK_CIPHER, call, "Cipher selects a weak algorithm or ECB transformation: " + raw);
        }
        if (emitter.enabled(LEGACY_TLS) && isStaticTypeCall(unit, call, "SSLContext", "javax.net.ssl.SSLContext")
            && Set.of("SSL", "SSLV2", "SSLV3", "TLSV1", "TLSV1.0", "TLSV1.1").contains(algorithm)) {
            emitter.emit(LEGACY_TLS, call, "SSLContext explicitly selects legacy protocol " + raw);
        }
    }

    private static boolean weakCipher(String algorithm) {
        String primitive = algorithm.split("/", -1)[0];
        return Set.of("DES", "DESEDE", "TRIPLEDES", "RC2", "RC4", "ARCFOUR").contains(primitive)
            || algorithm.contains("/ECB/") || algorithm.endsWith("/ECB");
    }

    private static void evaluateHardcodedKey(ObjectCreationExpr creation, Emitter emitter) {
        String type = simpleName(creation.getType().asString());
        if (!("SecretKeySpec".equals(type) || "PBEKeySpec".equals(type)) || creation.getArguments().isEmpty()) return;
        ExpressionFacts.Fact key = ExpressionFacts.inspect(creation.getArgument(0));
        if (key.hardcodedBytes() || ("PBEKeySpec".equals(type) && key.constant() != null && !key.dynamic())) {
            emitter.emit(HARDCODED_KEY, creation, type + " is constructed from key material embedded in source code");
        }
    }

    private static void evaluateHostnameCall(MethodCallExpr call, Emitter emitter) {
        if (!Set.of("setHostnameVerifier", "setDefaultHostnameVerifier", "hostnameVerifier")
            .contains(call.getNameAsString()) || call.getArguments().isEmpty()) return;
        Expression verifier = call.getArgument(0);
        if (verifier.isLambdaExpr() && alwaysTrue(verifier.asLambdaExpr())) {
            emitter.emit(TRUST_HOSTNAME, verifier, "hostname verifier always returns true and accepts every host");
        }
    }

    private static void evaluateHostnameImplementations(CompilationUnit unit, Emitter emitter) {
        for (MethodDeclaration method : sorted(unit.findAll(MethodDeclaration.class))) {
            if ("verify".equals(method.getNameAsString()) && returnsOnlyTrue(method)
                && insideImplementation(method, "HostnameVerifier")) {
                emitter.emit(TRUST_HOSTNAME, method, "HostnameVerifier.verify always returns true and accepts every host");
            }
        }
    }

    private static void evaluateTrustManagers(CompilationUnit unit, Emitter emitter) {
        Set<Node> emittedContainers = new HashSet<>();
        for (MethodDeclaration method : sorted(unit.findAll(MethodDeclaration.class))) {
            if (!("checkClientTrusted".equals(method.getNameAsString())
                || "checkServerTrusted".equals(method.getNameAsString()))) continue;
            if (method.getBody().isEmpty() || !method.getBody().get().getStatements().isEmpty()) continue;
            Node container = implementationContainer(method, "X509TrustManager");
            if (container != null && emittedContainers.add(container)) {
                emitter.emit(TRUST_X509, method, "X509TrustManager trust checks are empty and accept unverified certificates");
            }
        }
    }

    private static void evaluateXxe(MethodCallExpr call, Emitter emitter) {
        String method = call.getNameAsString();
        if ("setFeature".equals(method) && call.getArguments().size() >= 2) {
            Optional<String> feature = ExpressionFacts.constantString(call.getArgument(0));
            Optional<Boolean> enabled = ExpressionFacts.constantBoolean(call.getArgument(1));
            if (feature.isPresent() && feature.get().length() <= 512 && enabled.isPresent()) {
                String normalized = feature.get().toLowerCase(Locale.ROOT);
                if ((enabled.get() && EXTERNAL_ENTITY_FEATURES.contains(normalized))
                    || (!enabled.get() && DISABLE_DTD_FEATURES.contains(normalized))) {
                    emitter.emit(XXE, call, "XML parser explicitly enables external entity or DTD processing");
                }
            }
            return;
        }
        if (("setExpandEntityReferences".equals(method) || "setXIncludeAware".equals(method))
            && !call.getArguments().isEmpty()
            && ExpressionFacts.constantBoolean(call.getArgument(0)).orElse(false)) {
            emitter.emit(XXE, call, "XML parser explicitly enables external entity expansion");
            return;
        }
        if (("setAttribute".equals(method) || "setProperty".equals(method)) && call.getArguments().size() >= 2) {
            String property = call.getArgument(0).toString().toLowerCase(Locale.ROOT);
            String value = ExpressionFacts.constantString(call.getArgument(1)).orElse("").trim();
            if ((property.contains("access_external_dtd") || property.contains("access_external_schema")
                || property.contains("accessexternaldtd") || property.contains("accessexternalschema"))
                && !value.isEmpty()) {
                emitter.emit(XXE, call, "XML parser permits external DTD or schema access");
            }
        }
    }

    private static void evaluateDeserialization(MethodCallExpr call, Emitter emitter) {
        if (!("readObject".equals(call.getNameAsString()) || "readUnshared".equals(call.getNameAsString()))
            || call.getScope().isEmpty()) return;
        Expression scope = call.getScope().get();
        String type = simpleName(ExpressionFacts.declaredType(scope, call));
        boolean objectInput = "ObjectInputStream".equals(type)
            || (scope.isObjectCreationExpr()
                && "ObjectInputStream".equals(simpleName(scope.asObjectCreationExpr().getType().asString())));
        if (objectInput) emitter.emit(DESERIALIZATION, call,
            "ObjectInputStream deserializes an object without an evident input filter");
    }

    private static void evaluateSql(MethodCallExpr call, Emitter emitter) {
        if (!SQL_METHODS.contains(call.getNameAsString()) || call.getArguments().isEmpty()) return;
        ExpressionFacts.Fact sql = ExpressionFacts.inspect(call.getArgument(0));
        if (sql.dynamic() && sql.concatenated() && SQL_TEXT.matcher(sql.literalText()).find()) {
            emitter.emit(SQL_INJECTION, call, "SQL text is assembled by concatenating a non-constant value");
        }
    }

    private static void evaluateCommand(MethodCallExpr call, Emitter emitter) {
        if (!"exec".equals(call.getNameAsString()) || call.getArguments().isEmpty() || call.getScope().isEmpty()) return;
        Expression scope = call.getScope().get();
        String type = simpleName(ExpressionFacts.declaredType(scope, call));
        boolean runtime = "Runtime".equals(type) || scope.toString().contains("Runtime.getRuntime()");
        if (runtime && ExpressionFacts.inspect(call.getArgument(0)).dynamic()) {
            emitter.emit(COMMAND_INJECTION, call, "Runtime.exec receives a command that is not compile-time constant");
        }
    }

    private static void evaluateProcessBuilder(ObjectCreationExpr creation, Emitter emitter) {
        if (!"ProcessBuilder".equals(simpleName(creation.getType().asString())) || creation.getArguments().isEmpty()) return;
        if (creation.getArguments().stream().anyMatch(argument -> ExpressionFacts.inspect(argument).dynamic())) {
            emitter.emit(COMMAND_INJECTION, creation, "ProcessBuilder receives a command that is not compile-time constant");
        }
    }

    private static void evaluateDynamicCode(MethodCallExpr call, Emitter emitter) {
        if (call.getArguments().isEmpty() || call.getScope().isEmpty()) return;
        String method = call.getNameAsString();
        Expression scope = call.getScope().get();
        String type = simpleName(ExpressionFacts.declaredType(scope, call));
        String renderedScope = scope.toString();
        boolean engine = "eval".equals(method)
            && ("ScriptEngine".equals(type) || type.endsWith("ScriptEngine") || renderedScope.contains("getEngineBy"));
        boolean el = Set.of("eval", "createValueExpression", "createMethodExpression").contains(method)
            && (Set.of("ELProcessor", "ExpressionFactory").contains(type) || renderedScope.contains("ExpressionFactory"));
        if ((engine || el) && ExpressionFacts.inspect(call.getArgument(0)).dynamic()) {
            emitter.emit(DYNAMIC_CODE, call, "dynamic script or expression text is evaluated at runtime");
        }
    }

    private static void evaluatePermissions(MethodCallExpr call, Emitter emitter) {
        String method = call.getNameAsString();
        if (Set.of("setReadable", "setWritable", "setExecutable").contains(method)
            && call.getScope().isPresent() && call.getArguments().size() >= 2) {
            String type = simpleName(ExpressionFacts.declaredType(call.getScope().get(), call));
            boolean enable = ExpressionFacts.constantBoolean(call.getArgument(0)).orElse(false);
            boolean ownerOnly = ExpressionFacts.constantBoolean(call.getArgument(1)).orElse(true);
            if ("File".equals(type) && enable && !ownerOnly) {
                emitter.emit(BROAD_PERMISSION, call, "File permission is granted to every user rather than only the owner");
            }
            return;
        }
        if ("fromString".equals(method) && !call.getArguments().isEmpty()
            && call.getScope().map(Object::toString).orElse("").endsWith("PosixFilePermissions")) {
            Optional<String> mode = ExpressionFacts.constantString(call.getArgument(0));
            if (mode.isPresent() && mode.get().length() == 9
                && (mode.get().charAt(7) == 'w' || mode.get().charAt(8) == 'x')) {
                emitter.emit(BROAD_PERMISSION, call, "POSIX mode grants write or execute permission to other users");
            }
        }
    }

    private static void evaluateCookie(MethodCallExpr call, Emitter emitter) {
        if (!"setSecure".equals(call.getNameAsString()) || call.getArguments().isEmpty()
            || call.getScope().isEmpty() || ExpressionFacts.constantBoolean(call.getArgument(0)).orElse(true)) return;
        if ("Cookie".equals(simpleName(ExpressionFacts.declaredType(call.getScope().get(), call)))) {
            emitter.emit(INSECURE_COOKIE, call, "cookie Secure protection is explicitly disabled");
        }
    }

    private static boolean isStaticTypeCall(CompilationUnit unit, MethodCallExpr call, String simple, String qualified) {
        if (call.getScope().isEmpty()) return false;
        String scope = call.getScope().get().toString();
        if (qualified.equals(scope)) return true;
        if (!simple.equals(scope)) return false;
        String packageName = qualified.substring(0, qualified.lastIndexOf('.'));
        for (ImportDeclaration imported : unit.getImports()) {
            if ((!imported.isAsterisk() && imported.getNameAsString().equals(qualified))
                || (imported.isAsterisk() && imported.getNameAsString().equals(packageName))) return true;
        }
        return false;
    }

    private static boolean alwaysTrue(LambdaExpr lambda) {
        Statement body = lambda.getBody();
        if (body.isExpressionStmt()) {
            Expression expression = body.asExpressionStmt().getExpression();
            return expression instanceof BooleanLiteralExpr literal && literal.getValue();
        }
        return body.isBlockStmt() && returnsOnlyTrue(body.asBlockStmt());
    }

    private static boolean returnsOnlyTrue(MethodDeclaration method) {
        return method.getBody().map(JavaAnalyzer::returnsOnlyTrue).orElse(false);
    }

    private static boolean returnsOnlyTrue(BlockStmt body) {
        if (body.getStatements().size() != 1 || !body.getStatement(0).isReturnStmt()) return false;
        ReturnStmt returned = body.getStatement(0).asReturnStmt();
        return returned.getExpression().filter(Expression::isBooleanLiteralExpr)
            .map(Expression::asBooleanLiteralExpr).map(BooleanLiteralExpr::getValue).orElse(false);
    }

    private static boolean insideImplementation(MethodDeclaration method, String interfaceName) {
        return implementationContainer(method, interfaceName) != null;
    }

    private static Node implementationContainer(MethodDeclaration method, String interfaceName) {
        Node current = method.getParentNode().orElse(null);
        while (current != null) {
            if (current instanceof ObjectCreationExpr creation && creation.getAnonymousClassBody().isPresent()) {
                return simpleName(creation.getType().asString()).equals(interfaceName) ? creation : null;
            }
            if (current instanceof ClassOrInterfaceDeclaration declaration) {
                return declaration.getImplementedTypes().stream()
                    .anyMatch(type -> simpleName(type.asString()).equals(interfaceName)) ? declaration : null;
            }
            if (current instanceof MethodDeclaration || current instanceof ConstructorDeclaration) return null;
            current = current.getParentNode().orElse(null);
        }
        return null;
    }

    private static String simpleName(String type) {
        if (type == null || type.isBlank()) return "";
        String withoutGeneric = type.replaceAll("<.*>", "");
        int dot = Math.max(withoutGeneric.lastIndexOf('.'), withoutGeneric.lastIndexOf('$'));
        return dot >= 0 ? withoutGeneric.substring(dot + 1) : withoutGeneric;
    }

    private static <T extends Node> List<T> sorted(List<T> nodes) {
        nodes.sort(Comparator.comparingInt((Node node) -> node.getBegin().map(position -> position.line).orElse(Integer.MAX_VALUE))
            .thenComparingInt(node -> node.getBegin().map(position -> position.column).orElse(Integer.MAX_VALUE)));
        return nodes;
    }


    private static final class Emitter {
        private final String path;
        private final List<Models.Finding> findings;
        private final Set<String> enabledRules;
        private final Set<String> dedupe = new HashSet<>();

        private Emitter(String path, List<Models.Finding> findings, Set<String> enabledRules) {
            this.path = path;
            this.findings = findings;
            this.enabledRules = Set.copyOf(enabledRules);
        }

        private boolean enabled(Rule rule) { return enabledRules.contains(rule.id()); }

        private void emit(Rule rule, Node node, String message) {
            emit(rule, node, message, Map.of("ruleFamily", rule.id()));
        }

        private void emit(Rule rule, Node node, String message, Map<String, Object> evidence) {
            if (!enabled(rule)) throw new IllegalStateException("disabled rule evaluated: " + rule.id());
            int line = node.getBegin().map(position -> position.line).orElse(1);
            int column = node.getBegin().map(position -> position.column).orElse(1);
            if (!dedupe.add(rule.id() + ':' + line + ':' + column)) return;
            findings.add(new Models.Finding(rule.id(), rule.severity(), rule.cwe(), path, line, column,
                rule.title(), message, evidence));
        }
    }

    record Analysis(List<Models.Finding> findings, List<String> diagnostics) {}
}
