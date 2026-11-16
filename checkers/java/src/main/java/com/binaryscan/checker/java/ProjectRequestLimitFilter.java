package com.binaryscan.checker.java;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.exc.StreamConstraintsException;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.*;
import java.nio.file.*;
import java.util.concurrent.Semaphore;

/** Bound untrusted JSON before Jackson creates request objects, including chunked transfer. */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
final class ProjectRequestLimitFilter extends OncePerRequestFilter {
    static final long BODY_LIMIT = 64L << 20;
    private final Semaphore bodies = new Semaphore(1);
    private static final JsonFactory JSON = JsonFactory.builder().streamReadConstraints(StreamReadConstraints.builder()
        .maxNestingDepth(32).maxStringLength(4 << 20).maxNumberLength(100).build()).build();
    @Override protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith("/v2/java/projects") || request.getMethod().equals("DELETE") || request.getMethod().equals("GET");
    }
    @Override protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (request.getContentLengthLong() > BODY_LIMIT) { reject(response, 413, "java_project_request_too_large"); return; }
        if (!bodies.tryAcquire()) { reject(response, 429, "java_project_request_busy"); return; }
        Path spool = null;
        try {
            spool = Files.createTempFile("java-project-request-", ".json");
            long total = 0;
            try (var output = Files.newOutputStream(spool)) {
                byte[] buffer = new byte[16 * 1024]; int count;
                while ((count = request.getInputStream().read(buffer)) >= 0) {
                    total += count;
                    if (total > BODY_LIMIT) { reject(response, 413, "java_project_request_too_large"); return; }
                    output.write(buffer, 0, count);
                }
            }
            if (total > 0) try (var parser = JSON.createParser(spool.toFile())) {
                int tokens = 0;
                while (parser.nextToken() != null) {
                    if (++tokens > 250_000) { reject(response, 413, "java_project_request_too_complex"); return; }
                    if (parser.currentToken().isScalarValue()) parser.getTextLength();
                }
            } catch (StreamConstraintsException limit) { reject(response, 413, "java_project_request_too_complex"); return; }
            catch (com.fasterxml.jackson.core.JsonProcessingException malformed) { reject(response, 400, "invalid_java_project_json"); return; }
            try (var input = Files.newInputStream(spool)) {
                long length = total;
                var bounded = new ServletInputStream() {
                    boolean finished;
                    public int read() throws IOException { int value = input.read(); finished = value < 0; return value; }
                    public int read(byte[] bytes, int offset, int count) throws IOException { int value = input.read(bytes, offset, count); finished = value < 0; return value; }
                    public boolean isFinished() { return finished; }
                    public boolean isReady() { return true; }
                    public void setReadListener(ReadListener listener) { throw new IllegalStateException("synchronous JSON request"); }
                };
                chain.doFilter(new HttpServletRequestWrapper(request) {
                    public ServletInputStream getInputStream() { return bounded; }
                    public BufferedReader getReader() { return new BufferedReader(new InputStreamReader(bounded, java.nio.charset.StandardCharsets.UTF_8)); }
                    public int getContentLength() { return (int) length; }
                    public long getContentLengthLong() { return length; }
                }, response);
            }
        } finally {
            if (spool != null) Files.deleteIfExists(spool);
            bodies.release();
        }
    }
    private static void reject(HttpServletResponse response, int status, String code) throws IOException {
        response.setStatus(status); response.setHeader("Connection", "close"); response.setContentType("application/json");
        response.getWriter().write("{\"error\":\"" + code + "\"}"); response.flushBuffer();
    }
}
