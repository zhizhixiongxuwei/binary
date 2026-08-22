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
        var findings = new ArrayList<Models.Finding>();
        for (Token token : tokens.getTokens()) {
            if (token.getType() != PseudoCLexer.Identifier) continue;
            Rule rule = RULES.get(token.getText());
            if (rule == null) continue;
            findings.add(new Models.Finding(
                rule.id(), rule.severity(), rule.cwe(), file.path(), token.getLine(),
                token.getCharPositionInLine() + 1, rule.title(), rule.message(),
                Map.of("symbol", token.getText())
            ));
        }
        return findings;
    }

    private record Rule(String id, String severity, String cwe, String title, String message) {}
}
