package com.binaryscan.checker.java;

import org.junit.jupiter.api.Test;

import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class JavaAnalyzerTest {
    @Test
    void keepsJavaParserUtf16ColumnForChineseAndEmoji() {
        String content = "class Demo { void run(String command) { String label = \"中文😀\"; Runtime.getRuntime().exec(command); } }";

        var analysis = new JavaAnalyzer().analyze(new Models.SourceFile("Unicode.java", content));

        assertEquals(1, analysis.findings().size());
        assertEquals(1, analysis.findings().getFirst().line());
        assertEquals(content.indexOf("Runtime") + 1, analysis.findings().getFirst().column());
    }

    @Test
    void restoresAllThirteenBinaryNewRuleFamilies() {
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
        assertTrue(analysis.findings().stream().allMatch(finding ->
            finding.line() >= 1 && finding.column() >= 1 && finding.cwe().startsWith("CWE-")));
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
