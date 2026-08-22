package com.binaryscan.checker.java;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@RestController
final class CheckController {
    private final JavaAnalyzer analyzer;

    CheckController(JavaAnalyzer analyzer) { this.analyzer = analyzer; }

    @GetMapping("/healthz")
    Map<String, String> health() { return Map.of("status", "ok", "checker", "java"); }

    @PostMapping("/v1/check")
    Models.CheckResponse check(@RequestBody Models.CheckRequest request) {
        validate(request);
        var findings = new ArrayList<Models.Finding>();
        var diagnostics = new ArrayList<String>();
        for (Models.SourceFile file : request.files()) {
            validatePath(file.path());
            JavaAnalyzer.Analysis result = analyzer.analyze(file);
            findings.addAll(result.findings());
            diagnostics.addAll(result.diagnostics());
        }
        String status = diagnostics.isEmpty() ? "complete" : "partial";
        if (findings.size() > 10_000) {
            findings = new ArrayList<>(findings.subList(0, 10_000));
            diagnostics.add("finding limit reached");
            status = "partial";
        }
        return new Models.CheckResponse("checker-v1", request.projectId(), status, findings, diagnostics);
    }

    private static void validate(Models.CheckRequest request) {
        if (request == null || !"checker-v1".equals(request.version()) || !"java".equals(request.language())
            || request.projectId() == null || request.files() == null || request.files().size() > 3000) {
            throw new InvalidRequest();
        }
        long bytes = request.files().stream().mapToLong(file -> file.content() == null ? 0 : file.content().length()).sum();
        if (bytes > 128L * 1024 * 1024 || request.files().stream().anyMatch(file -> file.content() == null)) {
            throw new InvalidRequest();
        }
    }

    private static void validatePath(String path) {
        if (path == null || path.isBlank() || path.startsWith("/") || path.contains("..") || path.contains("\\")) {
            throw new InvalidRequest();
        }
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    private static final class InvalidRequest extends RuntimeException {}
}
