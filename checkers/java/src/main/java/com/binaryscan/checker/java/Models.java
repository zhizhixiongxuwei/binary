package com.binaryscan.checker.java;

import java.util.List;
import java.util.Map;

/** Java Checker 与 scanner 共享的 checker-v1 请求、Finding 和响应数据结构。 */
final class Models {
    private Models() {}
    record SourceFile(String path, String content) {}
    record CheckRequest(String version, String projectId, String language, List<SourceFile> files,
                        List<String> ruleIds, String catalogVersion) {}
    record Finding(String ruleId, String severity, String cwe, String path, int line, int column,
                   String title, String message, Map<String, Object> evidence) {}
    record CheckResponse(String version, String projectId, String status,
                         List<Finding> findings, List<String> diagnostics,
                         String catalogVersion, List<String> appliedRuleIds,
                         Coverage coverage, List<Diagnostic> diagnosticDetails,
                         boolean findingsTruncated, boolean diagnosticsTruncated, Map<String,Object> modelSummary) {
        CheckResponse(String version, String projectId, String status, List<Finding> findings,
                      List<String> diagnostics, String catalogVersion, List<String> appliedRuleIds,
                      Coverage coverage, List<Diagnostic> diagnosticDetails,
                      boolean findingsTruncated, boolean diagnosticsTruncated) {
            this(version, projectId, status, findings, diagnostics, catalogVersion, appliedRuleIds,
                coverage, diagnosticDetails, findingsTruncated, diagnosticsTruncated, Map.of());
        }
        CheckResponse(String version, String projectId, String status, List<Finding> findings,
                      List<String> diagnostics, String catalogVersion, List<String> appliedRuleIds) {
            this(version, projectId, status, findings, diagnostics, catalogVersion, appliedRuleIds,
                new Coverage(0, 0, 0, 0, 0, 0, 0), List.of(), false, false);
        }
    }
    // Methods means explicit ordinary method bodies, excluding abstract signatures,
    // constructors and initializer blocks. Constructors/initializers are still locally visited.
    record Coverage(int totalFiles, int parsedFiles, int failedFiles, int analyzedFiles,
                    int totalMethods, int analyzedMethods, int unresolvedCalls) {}
    record Diagnostic(String code, String path, int line, int column, String message) {}
    record ProjectFile(String path, String sha256, long sizeBytes) {}
    record ProjectRequest(String version, String projectId, String runId, String manifestSha256,
                          String catalogVersion, List<String> ruleIds, List<ProjectFile> files,
                          Map<String,String> frameworks, String frameworksSha256, String inputSha256) {
        ProjectRequest(String version, String projectId, String runId, String manifestSha256,
                       String catalogVersion, List<String> ruleIds, List<ProjectFile> files) {
            this(version, projectId, runId, manifestSha256, catalogVersion, ruleIds, files, Map.of(), null, null);
        }
    }
    record ProjectSession(String version, String sessionId) {}
    record ProjectUpload(List<SourceFile> files) {}
}
