package com.binaryscan.checker.java;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class SpotBugsReportTest {
    @TempDir Path temp;

    @Test
    void reportsActualDereferenceOffsetWithoutInventingASourceLine() throws IOException {
        var result = parse("""
            <BugCollection version="4.10.4">
              <BugInstance type="NP_LOAD_OF_KNOWN_NULL_VALUE" priority="3"/>
              <BugInstance type="NP_ALWAYS_NULL" priority="1">
                <Method classname="sample.Demo" name="run" signature="()I" primary="true"/>
                <LongMessage>Null pointer dereference</LongMessage>
                <SourceLine primary="true" start="42" startBytecode="3"/>
                <SourceLine classname="sample.Demo" role="SOURCE_LINE_DEREF" startBytecode="5" endBytecode="5"/>
              </BugInstance>
              <Errors errors="0" missingClasses="0"/>
            </BugCollection>
            """);
        assertEquals("complete", result.status());
        assertEquals(1, result.findings().size());
        var finding = result.findings().getFirst();
        assertEquals("NP_ALWAYS_NULL", finding.pattern());
        assertEquals("sample.Demo", finding.className());
        assertEquals("()I", finding.methodDescriptor());
        assertEquals(5, finding.bytecodeOffset());
        assertEquals("SOURCE_LINE_DEREF", finding.locationRole());
        assertNull(finding.originalLine());
        assertNull(finding.sourcePath());
    }

    @Test
    void marksMissingDependenciesAndMalformedReportsPartial() throws IOException {
        var result = parse("""
            <BugCollection version="4.10.4">
              <Errors errors="0" missingClasses="2"/>
            </BugCollection>
            """);
        assertEquals("partial", result.status());
        assertEquals("SpotBugs reported 2 missing classes", result.diagnostics().getFirst());

        result = parse("""
            <!DOCTYPE BugCollection [<!ENTITY payload SYSTEM "file:///missing">]>
            <BugCollection version="4.10.4">&payload;<Errors errors="0" missingClasses="0"/></BugCollection>
            """);
        assertEquals("partial", result.status());
        assertTrue(result.findings().isEmpty());
    }

    private SpotBugsReport.Result parse(String report) throws IOException {
        return SpotBugsReport.parse(Files.writeString(temp.resolve("report.xml"), report));
    }
}
