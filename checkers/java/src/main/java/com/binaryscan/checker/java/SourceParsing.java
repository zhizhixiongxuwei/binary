package com.binaryscan.checker.java;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ParseProblemException;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.type.Type;

/** Per-invocation configuration: never mutate StaticJavaParser's shared defaults. */
final class SourceParsing {
    private SourceParsing() {}
    private static JavaParser parser() {
        return new JavaParser(new ParserConfiguration().setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_21));
    }
    static CompilationUnit parse(String content) {
        var result = parser().parse(content);
        if (!result.isSuccessful() || result.getResult().isEmpty()) throw new ParseProblemException(result.getProblems());
        return result.getResult().orElseThrow();
    }
    static Type type(String name) {
        return parser().parseType(name).getResult().orElse(null);
    }
    static Models.Diagnostic diagnostic(String path, ParseProblemException exception) {
        var problem = exception.getProblems().isEmpty() ? null : exception.getProblems().getFirst();
        var position = problem == null ? null : problem.getLocation().flatMap(range -> range.getBegin().getRange())
            .map(range -> range.begin).orElse(null);
        String message = problem == null ? "Java source could not be parsed" : problem.getMessage();
        message = message.substring(0, Math.min(message.length(), 768));
        return new Models.Diagnostic("JAVA_PARSE_ERROR", path, position == null ? 1 : position.line,
            position == null ? 1 : position.column, message);
    }
}
