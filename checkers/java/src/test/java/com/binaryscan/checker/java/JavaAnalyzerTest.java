package com.binaryscan.checker.java;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

final class JavaAnalyzerTest {
    @Test
    void keepsJavaParserUtf16ColumnForChineseAndEmoji() {
        String content = "class Demo { void run() { String label = \"中文😀\"; Runtime.getRuntime().exec(\"id\"); } }";

        var analysis = new JavaAnalyzer().analyze(new Models.SourceFile("Unicode.java", content));

        assertEquals(1, analysis.findings().size());
        assertEquals(1, analysis.findings().getFirst().line());
        assertEquals(content.indexOf("Runtime") + 1, analysis.findings().getFirst().column());
        assertEquals(50, analysis.findings().getFirst().column());
    }
}
