package com.binaryscan.checker.java;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

final class SpotBugsAnalyzerTest {
    @TempDir Path temp;

    @Test
    void validatesArchiveBeforeInvokingTheAnalyzer() throws IOException {
        assertDoesNotThrow(() -> SpotBugsAnalyzer.validate("jar", jar("lib/dependency.jar")));
        Path unsafe = jar("../dependency.jar");
        var error = assertThrows(ResponseStatusException.class, () -> SpotBugsAnalyzer.validate("jar", unsafe));
        assertEquals(HttpStatus.BAD_REQUEST, error.getStatusCode());
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
