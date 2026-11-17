package com.binaryscan.checker.java;

import jakarta.annotation.PreDestroy;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;

/** Isolated, manifest-bound upload sessions. The checker never accepts host filesystem paths. */
@RestController
final class ProjectCheckController {
    static final long PROJECT_BYTES = 64L << 20, GLOBAL_BYTES = 128L << 20;
    static final long TTL_MILLIS = Duration.ofMinutes(15).toMillis();
    private final JavaAnalyzer analyzer;
    private final Map<String, Session> sessions = new HashMap<>();
    private long reservedBytes;
    private final ScheduledExecutorService reaper = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread thread = new Thread(r, "java-project-expiry"); thread.setDaemon(true); return thread;
    });
    ProjectCheckController(JavaAnalyzer analyzer) {
        this.analyzer = analyzer;
        reaper.scheduleWithFixedDelay(this::expire, 1, 1, TimeUnit.MINUTES);
    }
    private static final class Session {
        String id, projectId, runId, manifestSha256;
        List<String> rules;
        Map<String,String> frameworks;
        String frameworksSha256, inputSha256;
        LinkedHashMap<String, Models.ProjectFile> expected = new LinkedHashMap<>();
        Map<String, Path> uploaded = new HashMap<>();
        Path root;
        long bytes;
        volatile long touched = System.currentTimeMillis();
        boolean running, released;
        volatile boolean cancelled;
        Thread thread;
        Models.CheckResponse result;
        volatile ProjectAnalyzer.Progress progress = new ProjectAnalyzer.Progress("java-project-v1", "uploading", 0, 1, 0);
    }
    @PostMapping("/v2/java/projects")
    Models.ProjectSession create(@RequestBody Models.ProjectRequest request) {
        expire();
        if (request == null || !"java-project-v1".equals(request.version()) || !identity(request.projectId()) || !identity(request.runId())
            || request.manifestSha256() == null || !request.manifestSha256().matches("(?:sha256:)?[a-f0-9]{64}")
            || request.catalogVersion() == null || request.ruleIds() == null || request.files() == null) throw bad("invalid Java project identity or manifest");
        final List<String> rules;
        try { rules = RuleCatalog.selection(request.ruleIds(), request.catalogVersion()); }
        catch (IllegalArgumentException failure) { throw bad(failure.getMessage()); }
        if (request.files().size() > 20_000) throw large();
        Session session = new Session(); session.id = UUID.randomUUID().toString().replace("-", "");
        session.projectId = request.projectId(); session.runId = request.runId(); session.manifestSha256 = request.manifestSha256(); session.rules = rules;
        session.frameworks = validateFrameworks(request);
        session.frameworksSha256 = request.frameworksSha256(); session.inputSha256 = request.inputSha256();
        for (var file : request.files()) {
            if (file == null || !safePath(file.path()) || file.sha256() == null || !file.sha256().matches("[a-f0-9]{64}")
                || file.sizeBytes() < 0 || file.sizeBytes() > (file.path().equals(DependencyIndex.PATH)?24L:4L) << 20 || session.expected.putIfAbsent(file.path(), file) != null) throw bad("invalid or duplicate source manifest entry");
            session.bytes += file.sizeBytes();
            if (session.bytes > PROJECT_BYTES) throw large();
        }
        synchronized (this) {
        for (Session existing : sessions.values()) if (existing.projectId.equals(session.projectId) && existing.runId.equals(session.runId)
            && existing.manifestSha256.equals(session.manifestSha256)) {
            if (!existing.rules.equals(session.rules) || !existing.expected.equals(session.expected)
                || !existing.frameworks.equals(session.frameworks) || !Objects.equals(existing.frameworksSha256, session.frameworksSha256)
                || !Objects.equals(existing.inputSha256, session.inputSha256)) throw conflict("pinned project session identity cannot be changed");
            existing.touched = System.currentTimeMillis();
            return new Models.ProjectSession("java-project-v1", existing.id);
        }
        if (sessions.size() >= 2 || reservedBytes + session.bytes > GLOBAL_BYTES)
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "Java project session budget is busy");
        try { session.root = Files.createTempDirectory("java-project-"); }
        catch (IOException failure) { throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "cannot allocate Java project workspace"); }
        sessions.put(session.id, session); reservedBytes += session.bytes;
        }
        return new Models.ProjectSession("java-project-v1", session.id);
    }
    @PutMapping("/v2/java/projects/{sessionId}/files")
    Map<String,Object> upload(@PathVariable("sessionId") String id, @RequestBody Models.ProjectUpload request) {
        Session session = get(id);
        synchronized (session) {
            if (session.cancelled || session.running || session.result != null) throw conflict("session is sealed or cancelled");
            if (request == null || request.files() == null || request.files().size() > 200) throw bad("invalid source batch");
            long bytes = 0;
            for (var source : request.files()) {
                if (source == null || source.content() == null || !safePath(source.path())) throw bad("invalid source file");
                byte[] contents = source.content().getBytes(StandardCharsets.UTF_8); bytes += contents.length;
                if (bytes > 32L << 20) throw large();
                var descriptor = session.expected.get(source.path());
                if (descriptor == null || descriptor.sizeBytes() != contents.length || !descriptor.sha256().equals(sha256(contents)))
                    throw bad("source file does not match the pinned project manifest");
                if (session.uploaded.containsKey(source.path())) continue; // Hash-verified retry is idempotent.
                try {
                    Path destination = session.root.resolve(Integer.toString(session.uploaded.size()) + ".java");
                    Files.write(destination, contents, StandardOpenOption.CREATE_NEW);
                    session.uploaded.put(source.path(), destination);
                } catch (IOException failure) { throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "cannot store project source"); }
            }
            session.touched = System.currentTimeMillis();
            return Map.of("uploadedFiles", session.uploaded.size());
        }
    }
    @GetMapping("/v2/java/projects/{sessionId}/progress")
    ProjectAnalyzer.Progress progress(@PathVariable("sessionId") String id) {
        Session session = get(id);
        session.touched = System.currentTimeMillis();
        return session.progress;
    }
    @PostMapping("/v2/java/projects/{sessionId}/analyze")
    Models.CheckResponse analyze(@PathVariable("sessionId") String id) {
        Session session = get(id);
        synchronized (session) {
            if (session.result != null) return session.result;
            if (session.cancelled || session.running) throw conflict("session is cancelled or already running");
            if (session.uploaded.size() != session.expected.size()) throw conflict("project manifest upload is incomplete");
            if (!AnalysisSlot.HEAVY.tryAcquire()) throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "Java analyzer is busy");
            session.running = true; session.thread = Thread.currentThread(); session.touched = System.currentTimeMillis();
        }
        try {
            List<ProjectAnalyzer.Input> files = session.expected.keySet().stream().sorted()
                .map(path -> new ProjectAnalyzer.Input(path, session.uploaded.get(path))).toList();
            var result = ProjectAnalyzer.analyze(session.projectId, files, session.rules, analyzer, new FrameworkContracts(session.frameworks), progress -> session.progress = progress,session.inputSha256);
            synchronized (session) { session.result = result; }
            return result;
        } catch (IOException failure) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Java project source became unavailable");
        } finally {
            AnalysisSlot.HEAVY.release();
            synchronized (session) { session.running = false; session.thread = null; }
            if (session.cancelled) release(session);
            Thread.interrupted();
        }
    }
    @DeleteMapping("/v2/java/projects/{sessionId}")
    Map<String,String> delete(@PathVariable("sessionId") String id) {
        Session session;
        synchronized (this) { session = sessions.remove(id); }
        if (session != null) cancel(session);
        return Map.of("status", "released");
    }
    private Session get(String id) {
        expire();
        synchronized (this) {
        if (id == null || !id.matches("[a-f0-9]{32}") || !sessions.containsKey(id))
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "unknown or expired Java project session");
        return sessions.get(id);
        }
    }
    private void expire() {
        long now = System.currentTimeMillis();
        List<Session> expired;
        synchronized (this) {
            expired = sessions.values().stream().filter(s -> now - s.touched > TTL_MILLIS).toList();
            for (Session session : expired) sessions.remove(session.id);
        }
        expired.forEach(this::cancel);
    }
    private void cancel(Session session) {
        synchronized (session) {
            session.cancelled = true;
            if (session.thread != null) session.thread.interrupt();
            if (!session.running) release(session);
        }
    }
    private void release(Session session) {
        synchronized (this) {
            if (session.released) return;
            session.released = true; reservedBytes -= session.bytes;
        }
        try (var paths = Files.walk(session.root)) {
            for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(path);
        } catch (IOException ignored) { /* Unique tmpfs workspace expires with the container. */ }
    }
    @PreDestroy void close() {
        reaper.shutdownNow();
        List<Session> remaining;
        synchronized (this) { remaining = List.copyOf(sessions.values()); sessions.clear(); }
        remaining.forEach(this::cancel);
    }
    private static boolean identity(String value) { return value != null && !value.isBlank() && value.length() <= 64 && value.chars().noneMatch(Character::isISOControl); }
    private static Map<String,String> validateFrameworks(Models.ProjectRequest request) {
        Map<String,String> frameworks = request.frameworks() == null ? Map.of() : request.frameworks();
        if (frameworks.size() > 512) throw bad("too many framework coordinates");
        for (var item : frameworks.entrySet()) if (item.getKey() == null || item.getValue() == null
            || item.getKey().length() > 256 || !item.getKey().matches("[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+")
            || item.getValue().length() > 128 || !item.getValue().matches("[A-Za-z0-9_.+\\-]+")) throw bad("invalid framework coordinate");
        if (request.inputSha256() != null && !request.inputSha256().matches("[a-f0-9]{64}")) throw bad("invalid original input identity");
        if (!frameworks.isEmpty() && (request.inputSha256() == null || request.frameworksSha256() == null)) throw bad("framework evidence is not bound to the original input");
        if (request.frameworksSha256() != null) {
            try {
                byte[] canonical = new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsBytes(new TreeMap<>(frameworks));
                if (!sha256(canonical).equals(request.frameworksSha256())) throw bad("framework evidence digest mismatch");
            } catch (com.fasterxml.jackson.core.JsonProcessingException invalid) { throw bad("invalid framework evidence"); }
        }
        return Map.copyOf(frameworks);
    }
    static boolean safePath(String path) {
        return path != null && !path.isBlank() && path.length() <= 1024 && !path.startsWith("/") && !path.contains("\\") && !path.contains(":")
            && path.chars().noneMatch(Character::isISOControl) && Arrays.stream(path.split("/", -1)).noneMatch(p -> p.isEmpty() || p.equals(".") || p.equals(".."));
    }
    static String sha256(byte[] bytes) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
        catch (java.security.NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }
    private static ResponseStatusException bad(String message) { return new ResponseStatusException(HttpStatus.BAD_REQUEST, message); }
    private static ResponseStatusException conflict(String message) { return new ResponseStatusException(HttpStatus.CONFLICT, message); }
    private static ResponseStatusException large() { return new ResponseStatusException(HttpStatus.PAYLOAD_TOO_LARGE, "Java project exceeds bounded source analysis limits"); }
}
