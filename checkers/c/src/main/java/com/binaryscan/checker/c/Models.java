package com.binaryscan.checker.c;

import java.util.List;
import java.util.Map;

final class Models {
    private Models() {}

    record SourceFile(String path, String content) {}
    record CheckRequest(String version, String projectId, String language, List<SourceFile> files) {}
    record Finding(
        String ruleId,
        String severity,
        String cwe,
        String path,
        int line,
        int column,
        String title,
        String message,
        Map<String, Object> evidence
    ) {}
    record CheckResponse(
        String version,
        String projectId,
        String status,
        List<Finding> findings,
        List<String> diagnostics
    ) {}
}
