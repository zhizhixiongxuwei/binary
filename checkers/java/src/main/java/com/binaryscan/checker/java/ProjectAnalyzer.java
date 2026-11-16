package com.binaryscan.checker.java;

import com.github.javaparser.ParseProblemException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

/** Reparse one file at a time; the retained project state is a bounded signature/summary index. */
final class ProjectAnalyzer {
    record Input(String path, Path file) {}
    private ProjectAnalyzer() {}
    static Models.CheckResponse analyze(String projectId, List<Input> files, List<String> rules, JavaAnalyzer analyzer) throws IOException {
        var context = new ProjectContext();
        var valid = new ArrayList<Input>();
        var details = new ArrayList<Models.Diagnostic>();
        var findings = new ArrayList<Models.Finding>();
        int parsed = 0, analyzed = 0, totalMethods = 0, analyzedMethods = 0;
        boolean truncated = false;
        try {
            for (Input file : files) {
                context.checkBudget();
                try {
                    var unit = SourceParsing.parse(Files.readString(file.file())); parsed++; valid.add(file);
                    totalMethods += (int) unit.findAll(com.github.javaparser.ast.body.MethodDeclaration.class).stream().filter(method -> method.getBody().isPresent()).count();
                    context.register(file.path(), unit);
                } catch (ParseProblemException exception) { details.add(SourceParsing.diagnostic(file.path(), exception)); }
            }
            if (rules.contains("java-null-dereference")) {
                boolean converged = false;
                for (int round = 0; round < 16; round++) {
                    context.changed = false;
                    for (Input file : valid) {
                        context.checkBudget();
                        analyzer.analyze(new Models.SourceFile(file.path(), Files.readString(file.file())), Set.of("java-null-dereference"), context);
                    }
                    if (!context.changed) { converged = true; break; }
                }
                if (!converged) details.add(new Models.Diagnostic("JAVA_FIXED_POINT_LIMIT", "", 1, 1,
                    "interprocedural analysis reached sixteen rounds; recursive or long call chains may be incomplete"));
            }
            context.recording = true; context.analyzed.clear();
            for (Input file : valid) {
                context.checkBudget();
                var result = analyzer.analyze(new Models.SourceFile(file.path(), Files.readString(file.file())), Set.copyOf(rules), context);
                if (result.parsed()) { analyzed++; analyzedMethods += result.methods(); }
                details.addAll(result.diagnosticDetails());
                for (var finding : result.findings()) {
                    if (findings.size() < 10_000) findings.add(finding); else truncated = true;
                }
            }
        } catch (ProjectContext.BudgetExceeded limit) {
            details.add(new Models.Diagnostic(limit.code, "", 1, 1, limit.getMessage()));
        }
        details.addAll(context.diagnostics.values());
        if (truncated) details.add(new Models.Diagnostic("JAVA_FINDING_LIMIT", "", 1, 1, "findings truncated at 10000"));
        // Unvisited files after cancellation/budget failure count as failed coverage, never as parsed.
        if (parsed + details.stream().filter(d -> d.code().equals("JAVA_PARSE_ERROR")).count() < files.size())
            details.add(new Models.Diagnostic("JAVA_FILES_NOT_ANALYZED", "", 1, 1, "some project files were not parsed before the analysis budget ended"));
        boolean diagnosticsTruncated = details.size() > 1000;
        var bounded = List.copyOf(details.subList(0, Math.min(1000, details.size())));
        var messages = bounded.stream().map(d -> d.path().isEmpty() ? d.message() : d.path() + ":" + d.line() + ": " + d.message()).toList();
        var coverage = new Models.Coverage(files.size(), parsed, files.size() - parsed, analyzed,
            totalMethods, Math.min(analyzedMethods, totalMethods), context.unresolved.size());
        return new Models.CheckResponse("checker-v1", projectId,
            details.isEmpty() && !truncated ? "complete" : "partial", List.copyOf(findings), messages,
            RuleCatalog.VERSION, rules, coverage, bounded, truncated, diagnosticsTruncated);
    }
}
