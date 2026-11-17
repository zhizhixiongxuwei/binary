package com.binaryscan.checker.java;

import com.github.javaparser.ParseProblemException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

/** Reparse one file at a time; the retained project state is a bounded signature/summary index. */
final class ProjectAnalyzer {
    record Input(String path, Path file) {}
    record Progress(String version, String phase, int current, int total, int round, String unit) {
        Progress(String version, String phase, int current, int total, int round) {
            this(version, phase, current, total, round, "steps");
        }
    }
    private ProjectAnalyzer() {}
    static Models.CheckResponse analyze(String projectId, List<Input> files, List<String> rules, JavaAnalyzer analyzer) throws IOException {
        return analyze(projectId, files, rules, analyzer, new FrameworkContracts(Map.of()));
    }
    static Models.CheckResponse analyze(String projectId, List<Input> files, List<String> rules, JavaAnalyzer analyzer, FrameworkContracts contracts) throws IOException {
        return analyze(projectId, files, rules, analyzer, contracts, progress -> {});
    }
    static Models.CheckResponse analyze(String projectId, List<Input> files, List<String> rules, JavaAnalyzer analyzer,
                                       FrameworkContracts contracts, java.util.function.Consumer<Progress> progress) throws IOException {
        return analyze(projectId,files,rules,analyzer,contracts,progress,null);
    }
    static Models.CheckResponse analyze(String projectId, List<Input> allFiles, List<String> rules, JavaAnalyzer analyzer,
                                       FrameworkContracts contracts, java.util.function.Consumer<Progress> progress,String inputSha256) throws IOException {
        var files=allFiles.stream().filter(f->f.path().endsWith(".java")).toList();
        var resources=allFiles.stream().filter(f->!f.path().endsWith(".java")&&!f.path().equals(DependencyIndex.PATH)).toList();
        // Fixed bounded work units keep progress monotonic across early convergence.
        int total = Math.max(1, files.size() * (rules.contains("java-null-dereference") ? 18 : 2));
        int[] done = {0};
        progress.accept(new Progress("java-project-v1", "indexing", 0, total, 0));
        var context = new ProjectContext(contracts);
        for(var file:allFiles)if(file.path().equals(DependencyIndex.PATH)) {
            try {DependencyIndex.load(Files.readString(file.file()),inputSha256,context);}
            catch(IOException|RuntimeException invalid){context.definitions.clear();context.types.clear();context.ambiguousTypes.clear();context.mapperRegistryComplete=false;context.diagnostics.put("type-index",new Models.Diagnostic("JAVA_TYPE_INDEX_INVALID",file.path(),1,1,"type metadata is unavailable or does not match the original input; no type assumptions were applied"));}
        }
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
                progress.accept(new Progress("java-project-v1", "indexing", ++done[0], total, 0));
            }
            if (SecurityAnalysis.enabled(Set.copyOf(rules))) {
                context.security=SecurityAnalysis.analyze(valid,resources,context,Set.copyOf(rules));
                findings.addAll(context.security.findings);
            }
            if (rules.contains("java-null-dereference")) {
                boolean converged = false;
                for (int round = 0; round < 16; round++) {
                    context.changed = false; done[0] = 0;
                    for (Input file : valid) {
                        context.checkBudget();
                        if(!context.skipFile(file.path())){
                            analyzer.analyze(new Models.SourceFile(file.path(), Files.readString(file.file())), Set.of("java-null-dereference"), context);
                            context.initializedFiles.add(file.path());
                        }
                        progress.accept(new Progress("java-project-v1", "analyzing", files.size() + round * files.size() + ++done[0], total, round + 1));
                    }
                    if (!context.changed) { converged = true; break; }
                }
                if (!converged) details.add(new Models.Diagnostic("JAVA_FIXED_POINT_LIMIT", "", 1, 1,
                    "interprocedural analysis reached sixteen rounds; recursive or long call chains may be incomplete"));
            }
            context.recording = true; context.analyzed.clear();
            done[0] = total - files.size();
            progress.accept(new Progress("java-project-v1", "analyzing", done[0], total, 0));
            for (Input file : valid) {
                context.checkBudget();
                var result = analyzer.analyze(new Models.SourceFile(file.path(), Files.readString(file.file())), Set.copyOf(rules), context);
                if (result.parsed()) { analyzed++; analyzedMethods += result.methods(); }
                details.addAll(result.diagnosticDetails());
                progress.accept(new Progress("java-project-v1", "analyzing", ++done[0], total, 0));
                for (var finding : result.findings()) {
                    if (findings.size() < 10_000) findings.add(finding); else truncated = true;
                }
            }
        } catch (ProjectContext.BudgetExceeded limit) {
            details.add(new Models.Diagnostic(limit.code, "", 1, 1, limit.getMessage()));
        } catch (RuntimeException failure) {
            // Keep actionable engine stack locations without serializing an
            // exception message that might contain source or configuration data.
            String stack=Arrays.stream(failure.getStackTrace()).filter(s->s.getClassName().startsWith("com.binaryscan.")).limit(12).map(Object::toString).collect(java.util.stream.Collectors.joining("; "));
            details.add(new Models.Diagnostic("JAVA_ANALYZER_INTERNAL_ERROR","",1,1,failure.getClass().getName()+": "+stack));
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
        progress.accept(new Progress("java-project-v1", "completed", total, total, 0));
        var model=new LinkedHashMap<String,Object>();model.put("modelVersion",NullDereferenceAnalyzer.MODEL_VERSION);model.put("frameworkContractVersion",contracts.version());model.put("frameworkContractDigest",contracts.modelDigest());model.put("proofs",List.copyOf(context.modelProofs.values()));model.put("proofsTruncated",context.proofsTruncated);
        model.put("dependencyTypeDefinitions",context.definitions.size());model.put("ambiguousTypes",context.ambiguousTypes.size());model.put("focusedContexts",context.focusedContexts);model.put("argumentContexts",context.methods.values().stream().mapToInt(m->m.variants.size()).sum());model.put("cachedVariantSkips",context.cachedVariantSkips);model.put("summaryDependencyEdges",context.dependencyCount);
        if(context.security!=null)model.put("security",context.security.summary);
        model.put("cachedFileSkips",context.cachedFileSkips);
        return new Models.CheckResponse("checker-v1", projectId,
            details.isEmpty() && !truncated ? "complete" : "partial", List.copyOf(findings), messages,
            RuleCatalog.VERSION, rules, coverage, bounded, truncated, diagnosticsTruncated,
            model);
    }
}
