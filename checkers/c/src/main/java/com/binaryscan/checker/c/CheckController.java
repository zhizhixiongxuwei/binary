package com.binaryscan.checker.c;

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
    private static final int MAX_FILES = 3000;
    private static final long MAX_BYTES = 128L * 1024 * 1024;
    private final CAnalyzer analyzer;

    CheckController(CAnalyzer analyzer) {
        this.analyzer = analyzer;
    }

    @GetMapping("/healthz")
    Map<String, String> health() {
        return Map.of("status", "ok", "checker", "c");
    }

    @PostMapping("/v1/check")
    Models.CheckResponse check(@RequestBody Models.CheckRequest request) {
        validate(request);
        var findings = new ArrayList<Models.Finding>();
        for (Models.SourceFile file : request.files()) {
            validatePath(file.path());
            findings.addAll(analyzer.analyze(file));
            if (findings.size() > 10_000) {
                return new Models.CheckResponse("checker-v1", request.projectId(), "partial",
                    findings.subList(0, 10_000), List.of("finding limit reached"));
            }
        }
        return new Models.CheckResponse("checker-v1", request.projectId(), "complete", findings, List.of());
    }

    private static void validate(Models.CheckRequest request) {
        if (request == null || !"checker-v1".equals(request.version()) || !"c".equals(request.language())
            || request.projectId() == null || request.files() == null || request.files().size() > MAX_FILES) {
            throw new InvalidRequest();
        }
        long bytes = request.files().stream().mapToLong(file -> file.content() == null ? 0 : file.content().length()).sum();
        if (bytes > MAX_BYTES || request.files().stream().anyMatch(file -> file.content() == null)) {
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
