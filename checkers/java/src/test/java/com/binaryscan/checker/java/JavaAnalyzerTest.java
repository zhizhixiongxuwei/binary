package com.binaryscan.checker.java;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class JavaAnalyzerTest {
    private static final String NULL_DEREFERENCE = "java-null-dereference";

    @Test
    void keepsJavaParserUtf16ColumnForChineseAndEmoji() {
        String content = "class Demo { void run(String command) { String label = \"中文😀\"; Runtime.getRuntime().exec(command); } }";

        var analysis = new JavaAnalyzer().analyze(new Models.SourceFile("Unicode.java", content));

        assertEquals(1, analysis.findings().size());
        assertEquals(1, analysis.findings().getFirst().line());
        assertEquals(content.indexOf("Runtime") + 1, analysis.findings().getFirst().column());
    }

    @Test
    void coversAllRegisteredRuleFamilies() {
        String content = """
            package example;
            import java.io.*;
            import java.security.MessageDigest;
            import java.sql.Statement;
            import java.io.File;
            import javax.crypto.Cipher;
            import javax.crypto.spec.SecretKeySpec;
            import javax.net.ssl.*;
            import javax.script.ScriptEngine;
            import javax.servlet.http.Cookie;
            import javax.xml.parsers.DocumentBuilderFactory;

            class Rules implements HostnameVerifier, X509TrustManager {
                public boolean verify(String host, SSLSession session) { return true; }
                public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String auth) {}
                public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String auth) {}
                public java.security.cert.X509Certificate[] getAcceptedIssuers() { return null; }

                int nullDereference() {
                    String text = null;
                    return text.length();
                }

                void scan(String user, InputStream raw) throws Exception {
                    MessageDigest.getInstance("MD5");
                    Cipher.getInstance("AES/ECB/PKCS5Padding");
                    SSLContext.getInstance("TLSv1.1");
                    new SecretKeySpec("embedded-key".getBytes(java.nio.charset.StandardCharsets.UTF_8), "AES");
                    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
                    factory.setFeature("http://xml.org/sax/features/external-general-entities", true);
                    ObjectInputStream objects = new ObjectInputStream(raw);
                    objects.readObject();
                    Statement statement = null;
                    String sql = "SELECT * FROM users WHERE name='" + user + "'";
                    statement.executeQuery(sql);
                    Runtime.getRuntime().exec(user);
                    new ProcessBuilder(user);
                    ScriptEngine engine = null;
                    engine.eval(user);
                    File file = null;
                    file.setWritable(true, false);
                    Cookie cookie = null;
                    cookie.setSecure(false);
                }
            }
            """;

        var analysis = new JavaAnalyzer().analyze(new Models.SourceFile("Rules.java", content));
        Set<String> actual = analysis.findings().stream()
            .map(Models.Finding::ruleId).collect(Collectors.toSet());

        assertEquals(Set.of(), Set.copyOf(analysis.diagnostics()));
        assertEquals(JavaAnalyzer.RULE_IDS, actual);
        for (String id : JavaAnalyzer.RULE_IDS) {
            var selected = new JavaAnalyzer().analyze(new Models.SourceFile("Rules.java", content), Set.of(id));
            assertEquals(0, selected.diagnostics().size(), id);
            assertEquals(Set.of(id), selected.findings().stream().map(Models.Finding::ruleId).collect(Collectors.toSet()), id);
        }
        assertTrue(analysis.findings().stream().allMatch(finding ->
            finding.line() >= 1 && finding.column() >= 1 && finding.cwe().startsWith("CWE-")));
    }

    @Test
    void reportsNullDereferencesWithDecompiledSourceLocations() {
        assertNullDereferences("""
            class Demo {
                int alias() {
                    String original = null;
                    String alias = original;
                    original = "ready";
                    return alias.length();
                }
                int assignment(boolean reset) {
                    String assigned = "ready";
                    if (reset) assigned = null;
                    return assigned.length();
                }
                String branch(Object candidate) {
                    if (candidate == null) return candidate.toString();
                    return "ready";
                }
                int field() {
                    Demo receiver = null;
                    return receiver.size;
                }
                int size;
                int accessArray() {
                    int[] array = null;
                    return array[0];
                }
                int arrayLength() {
                    int[] values = null;
                    return values.length;
                }
                int conditional(String item) {
                    return item == null ? item.length() : 0;
                }
            }
            """, "alias.length()", "assigned.length()", "candidate.toString()", "receiver.size", "array[0]", "values.length",
            "item.length()");
    }

    @Test
    void respectsNullGuardsShortCircuitAndStaticMembers() {
        assertNullDereferences("""
            import vendor.ExternalType;
            import java.util.Objects;
            class Demo {
                static int CODE;
                static void ping() {}
                int unknownParameter(String input) { return input.length(); }
                int returnGuard(String input) {
                    if (input == null) return 0;
                    return input.length();
                }
                int throwGuard(String input) {
                    if (input == null) throw new IllegalArgumentException();
                    return input.length();
                }
                boolean shortCircuit(String input) {
                    return (input == null || input.length() == 0) || (input != null && input.length() > 3);
                }
                int staticMembers() {
                    Demo receiver = null;
                    receiver.ping();
                    return receiver.CODE;
                }
                void unresolvedMember() {
                    ExternalType receiver = null;
                    receiver.doWork();
                }
                int afterDereference(String checked) {
                    checked.length();
                    if (checked == null) return checked.length();
                    return 0;
                }
                int objectsGuard() {
                    String value = null;
                    if (Objects.nonNull(value)) return value.length();
                    return 0;
                }
                int instanceOfGuard() {
                    Object value = null;
                    if (value instanceof String) return ((String) value).length();
                    return 0;
                }
                boolean badShortCircuit(String candidate) {
                    return candidate == null && candidate.length() > 0;
                }
            }
            """, "candidate.length()");
    }

    private static void assertNullDereferences(String content, String... expressions) {
        String path = "example/Demo.java";
        var analysis = new JavaAnalyzer().analyze(new Models.SourceFile(path, content), Set.of(NULL_DEREFERENCE));
        var lines = content.lines().toList();
        var expected = new ArrayList<SourceLocation>();
        for (String expression : expressions) {
            for (int line = 0; line < lines.size(); line++) {
                int column = lines.get(line).indexOf(expression);
                if (column >= 0) expected.add(new SourceLocation(line + 1, column + 1));
            }
        }

        assertEquals(List.of(), analysis.diagnostics());
        assertEquals(expressions.length, expected.size());
        assertEquals(expected, analysis.findings().stream()
            .map(finding -> new SourceLocation(finding.line(), finding.column())).toList(), analysis.findings().toString());
        assertTrue(analysis.findings().stream().allMatch(finding -> NULL_DEREFERENCE.equals(finding.ruleId())
            && "CWE-476".equals(finding.cwe()) && path.equals(finding.path())));
    }

    private record SourceLocation(int line, int column) {}

    @Test
    void marksOnlyUnambiguousDereferenceSpansForCorrelation() {
        var source = new Models.SourceFile("Probe.java", """
            class Probe {
                int unique() {
                    int[] values = null;
                    return values.length;
                }
                int ambiguous(String safe) {
                    String text = null;
                    return safe
                        .length() + text.length();
                }
            }
            """);
        var result = new JavaAnalyzer().analyze(source, Set.of(NULL_DEREFERENCE));
        assertEquals(List.of(), result.diagnostics());
        assertEquals(2, result.findings().size());
        var array = result.findings().get(0).evidence();
        assertEquals("array-length", array.get("dereferenceKind"));
        assertEquals(true, array.get("uniqueDereferenceOnLine"));
        var call = result.findings().get(1).evidence();
        assertEquals("instance-method", call.get("dereferenceKind"));
        assertEquals("length", call.get("dereferenceMember"));
        assertEquals(false, call.get("uniqueDereferenceOnLine"));
    }

    @Test
    void avoidsSecureAndConstantCommandForms() {
        String content = """
            import java.security.MessageDigest;
            import javax.crypto.Cipher;
            import javax.net.ssl.SSLContext;
            class Safe {
              void run() throws Exception {
                MessageDigest.getInstance("SHA-256");
                Cipher.getInstance("AES/GCM/NoPadding");
                SSLContext.getInstance("TLSv1.3");
                Runtime.getRuntime().exec("/usr/bin/id");
              }
            }
            """;

        var analysis = new JavaAnalyzer().analyze(new Models.SourceFile("Safe.java", content));

        assertEquals(0, analysis.findings().size());
        assertEquals(0, analysis.diagnostics().size());
    }
}
