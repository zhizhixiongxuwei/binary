package com.binaryscan.checker.java;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;

/** Receives only bounded streams of JVM artifacts from the Scanner. */
@RestController
final class BytecodeCheckController {
    private final SpotBugsAnalyzer analyzer;

    BytecodeCheckController(SpotBugsAnalyzer analyzer) {
        this.analyzer = analyzer;
    }

    @PostMapping(path = "/v1/bytecode/check", consumes = MediaType.APPLICATION_OCTET_STREAM_VALUE)
    SpotBugsReport.Result check(@RequestParam("format") String format, HttpServletRequest request) throws IOException {
        if (!"jar".equals(format) && !"class".equals(format)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "unsupported bytecode format");
        }
        if (request.getContentLengthLong() > SpotBugsAnalyzer.INPUT_LIMIT) {
            throw new ResponseStatusException(HttpStatus.PAYLOAD_TOO_LARGE, "bytecode input is too large");
        }
        return analyzer.analyze(format, request.getInputStream());
    }
}
