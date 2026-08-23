package com.binaryscan.checker.c;

import com.binaryscan.checker.c.grammar.PseudoCLexer;
import org.antlr.v4.runtime.CharStreams;
import org.antlr.v4.runtime.CommonTokenStream;
import org.antlr.v4.runtime.Token;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Component
final class CAnalyzer {
    private static final Map<String, Rule> RULES = Map.of(
        "gets", new Rule("C001", "high", "CWE-242", "Use of gets", "gets cannot enforce a destination bound"),
        "strcpy", new Rule("C002", "high", "CWE-120", "Unbounded string copy", "strcpy may overflow the destination buffer"),
        "strcat", new Rule("C003", "high", "CWE-120", "Unbounded string concatenation", "strcat may overflow the destination buffer"),
        "sprintf", new Rule("C004", "medium", "CWE-120", "Unbounded formatted output", "sprintf does not receive the destination capacity"),
        "system", new Rule("C005", "high", "CWE-78", "Command execution", "system executes a command through the host shell"),
        "popen", new Rule("C006", "high", "CWE-78", "Shell process execution", "popen executes a command through the host shell")
    );

    List<Models.Finding> analyze(Models.SourceFile file) {
        var lexer = new PseudoCLexer(CharStreams.fromString(file.content()));
        var tokens = new CommonTokenStream(lexer);
        tokens.fill();
        var sourceLines = file.content().split("\\n", -1);
        var findings = new ArrayList<Models.Finding>();
        for (Token token : tokens.getTokens()) {
            if (token.getType() != PseudoCLexer.Identifier) continue;
            Rule rule = RULES.get(token.getText());
            if (rule == null) continue;
            findings.add(new Models.Finding(
                rule.id(), rule.severity(), rule.cwe(), file.path(), token.getLine(),
                utf16Column(sourceLines, token.getLine(), token.getCharPositionInLine()),
                rule.title(), rule.message(),
                Map.of("symbol", token.getText())
            ));
        }
        return findings;
    }

    /**
     * ANTLR's CodePointCharStream reports a zero-based Unicode code-point
     * offset. Java String indexes, like Monaco columns, count UTF-16 code
     * units, so offsetByCodePoints performs the required conversion.
     */
    private static int utf16Column(String[] sourceLines, int line, int codePointOffset) {
        if (line < 1 || line > sourceLines.length || codePointOffset < 0) return 1;
        String sourceLine = sourceLines[line - 1];
        int codePointCount = sourceLine.codePointCount(0, sourceLine.length());
        if (codePointOffset > codePointCount) return 1;
        return sourceLine.offsetByCodePoints(0, codePointOffset) + 1;
    }

    private record Rule(String id, String severity, String cwe, String title, String message) {}
}
