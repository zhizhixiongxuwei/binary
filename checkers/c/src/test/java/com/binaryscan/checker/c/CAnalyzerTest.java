package com.binaryscan.checker.c;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

final class CAnalyzerTest {
    @Test
    void convertsAntlrCodePointColumnToMonacoUtf16Column() {
        String content = "const char *label = \"😀中文\"; gets(buffer);";
        var findings = new CAnalyzer().analyze(new Models.SourceFile("unicode.c", content));

        assertEquals(1, findings.size());
        assertEquals(1, findings.getFirst().line());
        assertEquals(content.indexOf("gets") + 1, findings.getFirst().column());
        assertEquals(29, findings.getFirst().column());
    }
}
