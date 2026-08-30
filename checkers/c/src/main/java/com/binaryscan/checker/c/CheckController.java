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

/**
 * checker-v1 协议适配层：完成请求边界校验、逐文件分析和统一响应封装。
 *
 * <p>控制器故意不承担规则判断。这样协议限额、路径安全和 HTTP 状态码可以独立于
 * {@link CAnalyzer} 演进，规则引擎也能在单元测试中脱离 Web 容器直接验证。</p>
 */
@RestController
final class CheckController {
    // 限额既保护 Checker 内存，也约束 scanner 与 Checker 之间的内部协议。
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
            // 大项目达到上限时返回 partial，而不是继续占用内存或让整个批次失败。
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
        // Checker 只接受项目内相对路径；禁止绝对路径、父目录跳转和 Windows 分隔符。
        // 这同时保证 Finding.path 能安全地映射回 scanner 已登记的源码文件。
        if (path == null || path.isBlank() || path.startsWith("/") || path.contains("..") || path.contains("\\")) {
            throw new InvalidRequest();
        }
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    private static final class InvalidRequest extends RuntimeException {}
}
