package com.binaryscan.checker.java;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;

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

    @Test
    void explainsAnalysisErrorsAndMissingClassesWithoutPublishingStackTraces() throws IOException {
        var result = parse("""
            <BugCollection version="4.10.4">
              <Errors errors="1" missingClasses="1">
                <Error>
                  <ErrorMessage><![CDATA[Cannot analyze app.Service#run()
            at hidden.SourceLine42()]]></ErrorMessage>
                  <Exception><![CDATA[java.lang.IllegalStateException: unsupported opcode
            at hidden.ExceptionFrame()]]></Exception>
                  <StackTrace><Frame>hidden.StackFrame()</Frame></StackTrace>
                </Error>
                <MissingClass>vendor.RequiredType</MissingClass>
              </Errors>
            </BugCollection>
            """);
        assertEquals("partial", result.status());
        assertEquals("SpotBugs reported 1 analysis errors", result.diagnostics().getFirst());
        assertTrue(result.diagnostics().contains("SpotBugs analysis error: Cannot analyze app.Service#run(); java.lang.IllegalStateException: unsupported opcode"));
        assertTrue(result.diagnostics().contains("SpotBugs missing class: vendor.RequiredType"));
        assertTrue(result.diagnostics().stream().noneMatch(d -> d.contains("hidden.")));
    }

    @Test
    void boundsErrorAndMissingDetailsIncludingUtf8Names() throws IOException {
        var errors = new StringBuilder();
        for (int index = 0; index < 25; index++) {
            errors.append("<Error><ErrorMessage>").append("类名".repeat(500)).append(index).append("</ErrorMessage>")
                .append("<Exception>java.lang.RuntimeException</Exception></Error>");
            errors.append("<MissingClass>vendor.Type").append(index).append("</MissingClass>");
        }
        var result = parse("<BugCollection version=\"4.10.4\"><Errors errors=\"25\" missingClasses=\"25\">" + errors + "</Errors></BugCollection>");
        assertEquals(20, result.diagnostics().stream().filter(d -> d.startsWith("SpotBugs analysis error:")).count());
        assertEquals(20, result.diagnostics().stream().filter(d -> d.startsWith("SpotBugs missing class:")).count());
        assertTrue(result.diagnostics().contains("SpotBugs analysis error details truncated at 20 entries"));
        assertTrue(result.diagnostics().contains("SpotBugs missing class details truncated at 20 entries"));
        assertTrue(result.diagnostics().size() <= 100);
        assertTrue(result.diagnostics().stream().allMatch(d -> d.getBytes(StandardCharsets.UTF_8).length <= 900));
        assertTrue(result.diagnostics().stream().noneMatch(d -> d.indexOf('\0') >= 0 || d.contains("\n")));
    }

    private SpotBugsReport.Result parse(String report) throws IOException {
        return SpotBugsReport.parse(Files.writeString(temp.resolve("report.xml"), report));
    }

    @Test void preservesExactReturnValueProducerForProofReview() throws IOException {
        String report = """
            <BugCollection version="4.10.4">
              <BugInstance type="NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE" priority="2">
                <Method classname="sample.Factory" name="run" signature="()V" primary="true"/>
                <Method classname="vendor.Factory" name="getObject" signature="()Ljava/util/Properties;" role="METHOD_CALLED"/>
                <SourceLine classname="sample.Factory" primary="true" role="SOURCE_LINE_INVOKED" startBytecode="78" endBytecode="78"/>
                <SourceLine classname="sample.Factory" role="SOURCE_LINE_KNOWN_NULL" startBytecode="75" endBytecode="75"/>
                %s
              </BugInstance><Errors errors="0" missingClasses="0"/>
            </BugCollection>
            """;
        var finding = parse(report.formatted("")).findings().getFirst();
        assertEquals(new SpotBugsReport.MethodIdentity("vendor.Factory", "getObject", "()Ljava/util/Properties;"), finding.returnValueSource());
        assertEquals(75, finding.nullSourceBytecodeOffset());
        assertEquals(78, finding.bytecodeOffset());
        finding = parse(report.formatted("<SourceLine classname=\"sample.Factory\" role=\"SOURCE_LINE_KNOWN_NULL\" startBytecode=\"70\" endBytecode=\"70\"/>")).findings().getFirst();
        assertNull(finding.nullSourceBytecodeOffset());
    }
}
