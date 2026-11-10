package com.binaryscan.checker.java;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashSet;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.jar.Attributes;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import java.util.zip.ZipException;
import java.util.zip.ZipFile;

@Component
final class SpotBugsAnalyzer {
    static final long INPUT_LIMIT = 64L << 20;
    private static final long EXPANDED_LIMIT = 256L << 20;
    private static final long REPORT_LIMIT = 8L << 20;
    private static final int MANIFEST_LIMIT = 1 << 20;
    private static final int ENTRY_LIMIT = 10_000;
    private static final byte[] CLASS_MAGIC = {(byte) 0xca, (byte) 0xfe, (byte) 0xba, (byte) 0xbe};
    private static final Logger LOG = LoggerFactory.getLogger(SpotBugsAnalyzer.class);

    // The Checker shares a fixed memory and tmpfs budget with its source endpoint.
    private final Semaphore slot = new Semaphore(1);
    private final Path toolJar;

    SpotBugsAnalyzer(@Value("${binaryscan.spotbugs.jar:/opt/spotbugs/lib/spotbugs.jar}") String toolJar) {
        this.toolJar = Path.of(toolJar).toAbsolutePath();
    }

    SpotBugsReport.Result analyze(String format, InputStream body) {
        if (!slot.tryAcquire()) {
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "bytecode analyzer is busy");
        }
        Path work = null;
        try {
            work = Files.createTempDirectory("bytecode-check-");
            Path input = work.resolve("input." + format);
            try (OutputStream output = Files.newOutputStream(input)) {
                transferWithinLimit(body, output, INPUT_LIMIT);
            }
            validate(format, input);
            Path filter = work.resolve("null-dereferences.xml");
            Files.writeString(filter, SpotBugsReport.filter());
            Path report = work.resolve("report.xml");
            return run(work, input, filter, report);
        } catch (LimitExceeded limit) {
            throw new ResponseStatusException(HttpStatus.PAYLOAD_TOO_LARGE, "bytecode input exceeds analysis limits");
        } catch (IOException failure) {
            return SpotBugsReport.partial("bytecode analyzer could not process the input");
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return SpotBugsReport.partial("bytecode analysis was interrupted");
        } finally {
            try {
                if (work != null) deleteWork(work);
            } finally {
                slot.release();
            }
        }
    }

    private SpotBugsReport.Result run(Path work, Path input, Path filter, Path report)
        throws IOException, InterruptedException {
        Path java = Path.of(System.getProperty("java.home"), "bin", "java");
        Path lib = toolJar.getParent();
        String annotations = lib.resolve("spotbugs-annotations.jar") + File.pathSeparator + lib.resolve("jsr305-3.0.2.jar");
        Process process = new ProcessBuilder(java.toString(), "-Xmx512m", "-XX:ActiveProcessorCount=2",
            "-Djava.io.tmpdir=" + work, "-Duser.home=" + work,
            "-jar", toolJar.toString(), "-textui", "-effort:max", "-low", "-nested:false", "-dontCombineWarnings",
            "-visitors", "FindNullDeref,FindNullDerefsInvolvingNonShortCircuitEvaluation",
            "-auxclasspath", annotations, "-include", filter.toString(), "-xml:withMessages", input.toString())
            .directory(work.toFile()).redirectError(ProcessBuilder.Redirect.DISCARD).start();
        var capture = new FutureTask<Void>(() -> {
            try (InputStream stream = process.getInputStream(); OutputStream output = Files.newOutputStream(report)) {
                transferWithinLimit(stream, output, REPORT_LIMIT);
                return null;
            } catch (IOException failure) {
                process.destroyForcibly();
                throw failure;
            }
        });
        Thread.ofVirtual().start(capture);
        try {
            if (!process.waitFor(90, TimeUnit.SECONDS)) {
                return SpotBugsReport.partial("SpotBugs analysis timed out");
            }
            capture.get(5, TimeUnit.SECONDS);
            if (process.exitValue() != 0) {
                return SpotBugsReport.partial("SpotBugs did not complete analysis");
            }
            return SpotBugsReport.parse(report);
        } catch (ExecutionException failure) {
            return SpotBugsReport.partial(failure.getCause() instanceof LimitExceeded
                ? "SpotBugs report exceeds the output limit" : "could not capture the SpotBugs report");
        } catch (TimeoutException failure) {
            return SpotBugsReport.partial("could not capture the SpotBugs report");
        } finally {
            if (process.isAlive()) {
                process.destroyForcibly();
                process.waitFor(5, TimeUnit.SECONDS);
            }
            capture.cancel(true);
        }
    }

    static void validate(String format, Path input) throws IOException {
        if ("class".equals(format)) {
            try (InputStream stream = Files.newInputStream(input)) {
                if (!isClass(stream)) throw malformed("invalid JVM class");
            }
            return;
        }
        try (ZipFile jar = new ZipFile(input.toFile())) {
            if (jar.size() > ENTRY_LIMIT) throw new LimitExceeded();
            var names = new HashSet<String>();
            long remaining = EXPANDED_LIMIT;
            int classes = 0;
            var entries = jar.entries();
            while (entries.hasMoreElements()) {
                var entry = entries.nextElement();
                String name = entry.getName();
                if (!safeEntry(name) || !names.add(name) || entry.getSize() < 0) {
                    throw malformed("invalid JAR entry");
                }
                if (entry.getSize() > remaining) throw new LimitExceeded();
                try (InputStream contents = jar.getInputStream(entry)) {
                    long size = 0;
                    if (!entry.isDirectory() && name.endsWith(".class")) {
                        if (remaining < CLASS_MAGIC.length) throw new LimitExceeded();
                        if (!isClass(contents)) throw malformed("invalid JVM class in JAR");
                        size = CLASS_MAGIC.length;
                        classes++;
                    }
                    if (JarFile.MANIFEST_NAME.equals(name)) {
                        int limit = (int) Math.min(remaining, MANIFEST_LIMIT);
                        byte[] manifest = contents.readNBytes(limit + 1);
                        if (manifest.length > limit) throw new LimitExceeded();
                        validateManifest(manifest);
                        size = manifest.length;
                    }
                    size += transferWithinLimit(contents, OutputStream.nullOutputStream(), remaining - size);
                    if (size != entry.getSize()) throw malformed("invalid JAR entry size");
                    remaining -= size;
                }
            }
            if (classes == 0) throw malformed("JAR does not contain JVM classes");
        } catch (ZipException invalid) {
            throw malformed("invalid JAR");
        }
    }

    private static boolean isClass(InputStream stream) throws IOException {
        return Arrays.equals(stream.readNBytes(CLASS_MAGIC.length), CLASS_MAGIC);
    }

    private static void validateManifest(byte[] bytes) {
        // SpotBugs resolves manifest Class-Path even when nested archive scanning is disabled.
        try {
            String classPath = new Manifest(new ByteArrayInputStream(bytes)).getMainAttributes()
                .getValue(Attributes.Name.CLASS_PATH);
            if (classPath != null && !classPath.isBlank()
                && Arrays.stream(classPath.trim().split("\\s+")).anyMatch(path -> !safeEntry(path))) {
                throw malformed("JAR manifest class path must stay within the analyzer work directory");
            }
        } catch (IOException invalid) {
            throw malformed("invalid JAR manifest");
        }
    }

    static boolean safeEntry(String name) {
        if (name.isEmpty() || name.startsWith("/") || name.contains("\\") || name.contains(":")
            || name.chars().anyMatch(Character::isISOControl)) return false;
        return Arrays.stream(name.split("/")).noneMatch(part -> part.isEmpty() || part.equals(".") || part.equals(".."));
    }

    private static ResponseStatusException malformed(String message) {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, message);
    }

    private static long transferWithinLimit(InputStream source, OutputStream target, long limit) throws IOException {
        byte[] buffer = new byte[16 * 1024];
        long total = 0;
        for (int size; (size = source.read(buffer)) != -1;) {
            if (size > limit - total) throw new LimitExceeded();
            target.write(buffer, 0, size);
            total += size;
        }
        return total;
    }

    private static void deleteWork(Path work) {
        try (var paths = Files.walk(work)) {
            for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
                Files.deleteIfExists(path);
            }
        } catch (IOException failure) {
            LOG.warn("could not remove bytecode analyzer temporary files");
        }
    }

    private static final class LimitExceeded extends IOException {}
}
