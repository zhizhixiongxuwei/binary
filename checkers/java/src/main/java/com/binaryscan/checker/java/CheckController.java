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
        java.nio.file.Path root = null;
        var staged = new ArrayList<java.nio.file.Path>();
        try {
            root = java.nio.file.Files.createTempDirectory("java-check-");
            var inputs = new ArrayList<ProjectAnalyzer.Input>();
            for (var file : request.files()) {
                validatePath(file.path());
                var destination = root.resolve(Integer.toString(staged.size()));
                java.nio.file.Files.writeString(destination, file.content()); staged.add(destination);
                inputs.add(new ProjectAnalyzer.Input(file.path(), destination));
            }
            return ProjectAnalyzer.analyze(request.projectId(), inputs, applied, analyzer);
        } catch (java.io.IOException failure) {
            throw new org.springframework.web.server.ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "bounded source analysis workspace unavailable");
        } finally {
            for(var file:staged)try{java.nio.file.Files.deleteIfExists(file);}catch(java.io.IOException ignored){}
            if(root!=null)try{java.nio.file.Files.deleteIfExists(root);}catch(java.io.IOException ignored){}
        }
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
        if (bytes > 128L * 1024 * 1024 || request.files().stream().anyMatch(file -> file.content().getBytes(StandardCharsets.UTF_8).length > ((DependencyIndex.PATH.equals(file.path())?24L:4L) << 20))) {
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
