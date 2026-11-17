package com.binaryscan.checker.java;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

/** Receives only bounded streams of JVM artifacts from the Scanner. */
@RestController
@ConditionalOnProperty(name = "binaryscan.bytecode.enabled", havingValue = "true")
@ConditionalOnProperty(name = "binaryscan.bytecode.enabled", havingValue = "true")
final class BytecodeCheckController {
    private final SpotBugsAnalyzer analyzer;

    BytecodeCheckController(SpotBugsAnalyzer analyzer) {
        this.analyzer = analyzer;
    }

    @PostMapping(path = "/v1/bytecode/check", consumes = MediaType.APPLICATION_OCTET_STREAM_VALUE)
    SpotBugsReport.Result check(@RequestParam("format") String format, HttpServletRequest request,
        @RequestHeader(value = "X-BinaryScan-Frameworks", required = false) String frameworks,
        @RequestHeader(value = "X-BinaryScan-Frameworks-SHA256", required = false) String frameworksSha256,
        @RequestHeader(value = "X-BinaryScan-Input-SHA256", required = false) String inputSha256) throws IOException {
        if (!"jar".equals(format) && !"class".equals(format) && !"bundle".equals(format)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "unsupported bytecode format");
        }
        if (request.getContentLengthLong() > SpotBugsAnalyzer.inputLimit(format)) {
            throw new ResponseStatusException(HttpStatus.PAYLOAD_TOO_LARGE, "bytecode input is too large");
        }
        FrameworkContracts contracts = contracts(frameworks, frameworksSha256, inputSha256);
        return contracts == null ? analyzer.analyze(format, request.getInputStream()) : analyzer.analyze(format, request.getInputStream(), contracts, inputSha256);
    }

    static FrameworkContracts contracts(String json, String digest, String inputSha256) {
        if (json == null && digest == null && inputSha256 == null) return null;
        try {
            if (json == null || json.getBytes(StandardCharsets.UTF_8).length > 8192 || digest == null || !digest.matches("[a-f0-9]{64}")
                || inputSha256 == null || !inputSha256.matches("[a-f0-9]{64}")) throw new IllegalArgumentException();
            var root = new ObjectMapper().enable(DeserializationFeature.FAIL_ON_READING_DUP_TREE_KEY)
                .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS).readTree(json);
            if (root == null || !root.isObject()) throw new IllegalArgumentException();
            Map<String,String> values = new LinkedHashMap<>();
            var fields = root.fields();
            while (fields.hasNext()) {
                var entry = fields.next();
                if (!entry.getValue().isTextual()) throw new IllegalArgumentException();
                values.put(entry.getKey(), entry.getValue().textValue());
            }
            var contracts = new FrameworkContracts(values);
            if (!contracts.frameworksSha256().equals(digest)) throw new IllegalArgumentException();
            return contracts;
        } catch (IOException | IllegalArgumentException invalid) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "framework metadata or input binding is invalid");
        }
    }
}
