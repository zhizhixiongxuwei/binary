package com.binaryscan.checker.java;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class SpotBugsAnalyzerTest {
    @TempDir Path temp;

    @Test
    void validatesArchiveBeforeInvokingTheAnalyzer() throws IOException {
        assertDoesNotThrow(() -> SpotBugsAnalyzer.validate("jar", jar("lib/dependency.jar")));
        Path unsafe = jar("../dependency.jar");
        var error = assertThrows(ResponseStatusException.class, () -> SpotBugsAnalyzer.validate("jar", unsafe));
        assertEquals(HttpStatus.BAD_REQUEST, error.getStatusCode());
    }

    @Test
    void bundleSeparatesTargetsAndDependenciesAndRejectsResources() throws IOException {
        Path bundle = bundle("targets/0000.jar", classesOnly("sample/App.class"), "deps/0000.jar", classesOnly("vendor/Dependency.class"));
        var prepared = SpotBugsAnalyzer.prepareBundle(bundle, Files.createDirectory(temp.resolve("prepared")));
        assertEquals(1, prepared.targets().size());
        assertEquals(1, prepared.dependencies().size());
        assertTrue(prepared.targets().getFirst().toString().contains("targets"));
        Path malicious = bundle("targets/0000.jar", jarBytes("META-INF/MANIFEST.MF", "Class-Path: http://example.invalid/x.jar".getBytes(StandardCharsets.UTF_8)));
        assertThrows(ResponseStatusException.class, () -> SpotBugsAnalyzer.prepareBundle(malicious, Files.createDirectory(temp.resolve("rejected"))));
    }

    @Test
    void bundleRejectsPathTraversalAndMissingTargets() throws IOException {
        Path unsafe = bundle("../targets/0000.jar", classesOnly("sample/App.class"));
        assertThrows(ResponseStatusException.class, () -> SpotBugsAnalyzer.prepareBundle(unsafe, temp));
        Path dependenciesOnly = bundle("deps/0000.jar", classesOnly("sample/App.class"));
        assertThrows(ResponseStatusException.class, () -> SpotBugsAnalyzer.prepareBundle(dependenciesOnly, Files.createDirectory(temp.resolve("deps-only"))));
    }

    private Path bundle(Object... entries) throws IOException {
        Path output = Files.createTempFile(temp, "bundle-", ".zip");
        try (var zip = new ZipOutputStream(Files.newOutputStream(output))) {
            for (int index = 0; index < entries.length; index += 2) {
                zip.putNextEntry(new ZipEntry((String) entries[index]));
                zip.write((byte[]) entries[index + 1]);
                zip.closeEntry();
            }
        }
        return output;
    }

    private byte[] classesOnly(String path) throws IOException {
        return jarBytes(path, new byte[]{(byte) 0xca, (byte) 0xfe, (byte) 0xba, (byte) 0xbe, 0, 0, 0, 61});
    }

    private byte[] jarBytes(String path, byte[] body) throws IOException {
        var output = new ByteArrayOutputStream();
        try (var jar = new ZipOutputStream(output)) {
            jar.putNextEntry(new ZipEntry(path)); jar.write(body); jar.closeEntry();
        }
        return output.toByteArray();
    }

    private Path jar(String classPath) throws IOException {
        Path output = Files.createTempFile(temp, "probe-", ".jar");
        try (var jar = new ZipOutputStream(Files.newOutputStream(output))) {
            jar.putNextEntry(new ZipEntry("META-INF/MANIFEST.MF"));
            jar.write(("Manifest-Version: 1.0\r\nClass-Path: " + classPath + "\r\n\r\n").getBytes(StandardCharsets.UTF_8));
            jar.closeEntry();
            jar.putNextEntry(new ZipEntry("sample/Probe.class"));
            jar.write(new byte[]{(byte) 0xca, (byte) 0xfe, (byte) 0xba, (byte) 0xbe});
            jar.closeEntry();
        }
        return output;
    }
}
