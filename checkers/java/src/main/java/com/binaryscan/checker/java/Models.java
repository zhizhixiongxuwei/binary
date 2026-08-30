package com.binaryscan.checker.java;

import java.util.List;
import java.util.Map;

/** Java Checker 与 scanner 共享的 checker-v1 请求、Finding 和响应数据结构。 */
final class Models {
    private Models() {}
    record SourceFile(String path, String content) {}
    record CheckRequest(String version, String projectId, String language, List<SourceFile> files) {}
    record Finding(String ruleId, String severity, String cwe, String path, int line, int column,
                   String title, String message, Map<String, Object> evidence) {}
    record CheckResponse(String version, String projectId, String status,
                         List<Finding> findings, List<String> diagnostics) {}
}
