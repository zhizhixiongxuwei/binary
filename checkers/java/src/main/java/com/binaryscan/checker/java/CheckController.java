package com.binaryscan.checker.java;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.nio.charset.StandardCharsets;

/**
 * Java Checker 的 HTTP 契约边界，负责校验、批处理、诊断合并与结果截断。
 * 语法解析失败属于单文件可诊断问题，因此返回 partial；协议、路径或资源限额不合法则返回 400。
 */
@RestController
final class CheckController {
    private final JavaAnalyzer analyzer;

    CheckController(JavaAnalyzer analyzer) { this.analyzer = analyzer; }

    @GetMapping("/healthz")
    Map<String, String> health() { return Map.of("status", "ok", "checker", "java"); }

    @PostMapping("/v1/check")
    Models.CheckResponse checkHttp(@RequestBody JsonNode payload) {
        if (payload == null || !payload.isObject()
            || (payload.has("ruleIds") && (!payload.get("ruleIds").isArray()
                || !java.util.stream.StreamSupport.stream(payload.get("ruleIds").spliterator(), false).allMatch(JsonNode::isTextual)))
            || (payload.has("catalogVersion") && !payload.get("catalogVersion").isTextual())) throw new InvalidRequest();
        try { return check(new ObjectMapper().convertValue(payload, Models.CheckRequest.class)); }
        catch (IllegalArgumentException failure) { throw new InvalidRequest(); }
    }

    Models.CheckResponse check(Models.CheckRequest request) {
        validate(request);
        if (!AnalysisSlot.HEAVY.tryAcquire()) throw new org.springframework.web.server.ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "Java analyzer is busy");
        try { return checkBounded(request); }
        finally { AnalysisSlot.HEAVY.release(); }
    }

    private Models.CheckResponse checkBounded(Models.CheckRequest request) {
        final List<String> applied;
        try { applied = RuleCatalog.selection(request.ruleIds(), request.catalogVersion()); }
        catch (IllegalArgumentException failure) { throw new InvalidRequest(); }
        var findings = new ArrayList<Models.Finding>();
        var diagnostics = new ArrayList<String>();
        var details = new ArrayList<Models.Diagnostic>();
        int parsed = 0, methods = 0;
        for (Models.SourceFile file : request.files()) {
            validatePath(file.path());
            JavaAnalyzer.Analysis result = analyzer.analyze(file, Set.copyOf(applied));
            findings.addAll(result.findings());
            diagnostics.addAll(result.diagnostics());
            details.addAll(result.diagnosticDetails());
            if (result.parsed()) { parsed++; methods += result.methods(); }
        }
        String status = diagnostics.isEmpty() ? "complete" : "partial";
        boolean findingsTruncated = findings.size() > 10_000;
        if (findingsTruncated) {
            // 对外契约明确标记 partial，调用方不会把“被截断”误解为完整无遗漏结果。
            findings = new ArrayList<>(findings.subList(0, 10_000));
            diagnostics.add("finding limit reached");
            status = "partial";
        }
        boolean diagnosticsTruncated = diagnostics.size() > 1000 || details.size() > 1000;
        return new Models.CheckResponse("checker-v1", request.projectId(), status, findings,
            List.copyOf(diagnostics.subList(0, Math.min(1000, diagnostics.size()))), RuleCatalog.VERSION, applied,
            new Models.Coverage(request.files().size(), parsed, request.files().size() - parsed, parsed, methods, methods, 0),
            List.copyOf(details.subList(0, Math.min(1000, details.size()))), findingsTruncated, diagnosticsTruncated);
    }

    @GetMapping("/v1/rules")
    Map<String, Object> rules() { return RuleCatalog.catalog(); }

    private static void validate(Models.CheckRequest request) {
        if (request == null || !"checker-v1".equals(request.version()) || !"java".equals(request.language())
            || request.projectId() == null || request.files() == null || request.files().size() > 3000) {
            throw new InvalidRequest();
        }
        if (request.files().stream().anyMatch(file -> file == null || file.content() == null)) throw new InvalidRequest();
        long bytes = request.files().stream().mapToLong(file -> file.content().getBytes(StandardCharsets.UTF_8).length).sum();
        if (bytes > 128L * 1024 * 1024 || request.files().stream().anyMatch(file -> file.content().getBytes(StandardCharsets.UTF_8).length > 4L << 20)) {
            throw new InvalidRequest();
        }
    }

    private static void validatePath(String path) {
        // 仅允许项目内相对路径，保证 Finding 可以安全定位到已经登记的源码制品。
        if (!ProjectCheckController.safePath(path)) {
            throw new InvalidRequest();
        }
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    private static final class InvalidRequest extends RuntimeException {}
}
