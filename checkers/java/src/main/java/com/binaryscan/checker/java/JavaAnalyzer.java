package com.binaryscan.checker.java;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Component
final class JavaAnalyzer {
    Analysis analyze(Models.SourceFile file) {
        var findings = new ArrayList<Models.Finding>();
        var diagnostics = new ArrayList<String>();
        try {
            var unit = StaticJavaParser.parse(file.content());
            for (MethodCallExpr call : unit.findAll(MethodCallExpr.class)) {
                String name = call.getNameAsString();
                String scope = call.getScope().map(Node::toString).orElse("");
                if ("exec".equals(name) && scope.contains("Runtime")) {
                    findings.add(finding(file.path(), call, "JAVA001", "high", "CWE-78",
                        "Runtime command execution", "Runtime.exec may execute attacker-controlled commands"));
                }
                if ("setFeature".equals(name) && call.toString().contains("external-general-entities")
                    && call.toString().endsWith("true)")) {
                    findings.add(finding(file.path(), call, "JAVA003", "high", "CWE-611",
                        "External XML entities enabled", "The parser enables external XML entity resolution"));
                }
            }
            for (ObjectCreationExpr creation : unit.findAll(ObjectCreationExpr.class)) {
                if ("ProcessBuilder".equals(creation.getType().getNameAsString())) {
                    findings.add(finding(file.path(), creation, "JAVA002", "medium", "CWE-78",
                        "Process creation", "ProcessBuilder creates an operating-system process"));
                }
            }
        } catch (RuntimeException exception) {
            diagnostics.add(file.path() + ": parser rejected decompiled source");
        }
        return new Analysis(findings, diagnostics);
    }

    private Models.Finding finding(String path, Node node, String rule, String severity, String cwe,
                                   String title, String message) {
        int line = node.getBegin().map(position -> position.line).orElse(1);
        int column = node.getBegin().map(position -> position.column).orElse(1);
        return new Models.Finding(rule, severity, cwe, path, line, column, title, message, Map.of());
    }

    record Analysis(List<Models.Finding> findings, List<String> diagnostics) {}
}
