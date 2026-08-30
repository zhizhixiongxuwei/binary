package com.binaryscan.checker.c;

import java.util.List;
import java.util.Map;

/**
 * C Checker 的 checker-v1 线协议模型。
 *
 * <p>这些 record 与 OpenAPI/后端契约字段保持稳定：Checker 只返回事实和诊断，任务、运行、
 * 源码制品及报告的持久化仍由 scanner/app 完成。</p>
 */
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
