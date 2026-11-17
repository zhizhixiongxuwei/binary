package com.binaryscan.checker.java;

import com.fasterxml.jackson.annotation.JsonInclude;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Parses only the null dereference evidence emitted by the pinned SpotBugs release. */
final class SpotBugsReport {
    private static final String TOOL_VERSION = "4.10.4";
    private static final int FINDING_LIMIT = 10_000;
    private static final int DETAIL_LIMIT = 20;
    private static final int DIAGNOSTIC_LIMIT = 100;
    // Scanner validates UTF-8 byte lengths, so a character limit alone would
    // reject diagnostics containing non-ASCII class or method names.
    private static final int DIAGNOSTIC_BYTES = 900;
    private static final List<String> PATTERNS = List.of(
        "NP_ALWAYS_NULL", "NP_ALWAYS_NULL_EXCEPTION", "NP_NULL_ON_SOME_PATH",
        "NP_NULL_ON_SOME_PATH_EXCEPTION", "NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE",
        "NP_GUARANTEED_DEREF", "NP_GUARANTEED_DEREF_ON_EXCEPTION_PATH", "NP_CLOSING_NULL");

    private SpotBugsReport() {}

    static String filter() {
        return "<FindBugsFilter><Match><Bug pattern=\"" + String.join(",", PATTERNS) + "\"/></Match></FindBugsFilter>";
    }

    static Result partial(String diagnostic) {
        return result(List.of(), List.of(diagnostic));
    }

    static Result parse(Path report) {
        try {
            var factory = DocumentBuilderFactory.newDefaultInstance();
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            factory.setExpandEntityReferences(false);
            var builder = factory.newDocumentBuilder();
            builder.setErrorHandler(new DefaultHandler());
            Element root = builder.parse(report.toFile()).getDocumentElement();
            if (!"BugCollection".equals(root.getTagName()) || !TOOL_VERSION.equals(root.getAttribute("version"))) {
                return partial("invalid SpotBugs report identity");
            }
            return findings(root);
        } catch (ParserConfigurationException | IOException | SAXException invalid) {
            return partial("invalid SpotBugs XML report");
        }
    }

    private static Result findings(Element root) {
        List<Finding> findings = new ArrayList<>();
        List<String> diagnostics = new ArrayList<>();
        Element errors = child(root, "Errors", "", "");
        Integer errorCount = errors == null ? null : integer(errors.getAttribute("errors"), 0);
        Integer missingCount = errors == null ? null : integer(errors.getAttribute("missingClasses"), 0);
        if (errorCount == null || missingCount == null) return partial("invalid SpotBugs report diagnostics");
        if (errorCount > 0) diagnostics.add("SpotBugs reported " + errorCount + " analysis errors");
        if (missingCount > 0) diagnostics.add("SpotBugs reported " + missingCount + " missing classes");
        errorDetails(errors, diagnostics);

        boolean invalidFinding = false;
        for (Node node = root.getFirstChild(); node != null; node = node.getNextSibling()) {
            if (!(node instanceof Element bug) || !"BugInstance".equals(bug.getTagName())) continue;
            String pattern = bug.getAttribute("type");
            if (!PATTERNS.contains(pattern)) continue;
            if (findings.size() == FINDING_LIMIT) {
                diagnostics.add("SpotBugs finding limit reached");
                break;
            }
            Finding finding = finding(bug, pattern);
            if (finding != null) findings.add(finding);
            else invalidFinding = true;
        }
        if (invalidFinding) diagnostics.add("SpotBugs report contains findings without valid JVM method identity");
        return result(findings, diagnostics);
    }

    private static void errorDetails(Element errors, List<String> diagnostics) {
        int errorDetails = 0, missingDetails = 0;
        boolean errorsTruncated = false, missingTruncated = false;
        for (Node node = errors.getFirstChild(); node != null; node = node.getNextSibling()) {
            if (!(node instanceof Element element)) continue;
            switch (element.getTagName()) {
                case "Error", "ErrorMessage", "Exception" -> {
                    if (errorDetails++ >= DETAIL_LIMIT) { errorsTruncated = true; continue; }
                    String message;
                    if ("Error".equals(element.getTagName())) {
                        String detail = firstLine(child(element, "ErrorMessage", "", ""));
                        String exception = firstLine(child(element, "Exception", "", ""));
                        message = detail.isEmpty() ? exception : exception.isEmpty() || detail.equals(exception) ? detail : detail + "; " + exception;
                        if (message.isEmpty()) message = firstLine(element);
                    } else message = firstLine(element);
                    if (message.isEmpty()) message = "details unavailable";
                    diagnostics.add(boundedDiagnostic("SpotBugs analysis error: " + message));
                }
                case "MissingClass" -> {
                    if (missingDetails++ >= DETAIL_LIMIT) { missingTruncated = true; continue; }
                    String name = firstLine(element);
                    diagnostics.add(boundedDiagnostic("SpotBugs missing class: " + (name.isEmpty() ? "identity unavailable" : name)));
                }
                default -> { /* Never include StackTrace, Frame or source blocks. */ }
            }
        }
        if (errorsTruncated) diagnostics.add("SpotBugs analysis error details truncated at 20 entries");
        if (missingTruncated) diagnostics.add("SpotBugs missing class details truncated at 20 entries");
    }

    // Read only direct text/CDATA and its first nonempty line. getTextContent()
    // on Error would also expose an entire nested stack trace or source block.
    private static String firstLine(Element element) {
        if (element == null) return "";
        for (Node node = element.getFirstChild(); node != null; node = node.getNextSibling()) {
            if (node.getNodeType() != Node.TEXT_NODE && node.getNodeType() != Node.CDATA_SECTION_NODE) continue;
            String text = node.getNodeValue();
            int offset = 0;
            while (offset < text.length()) {
                int end = offset;
                while (end < text.length() && text.charAt(end) != '\n' && text.charAt(end) != '\r') end++;
                String line = text.substring(offset, end).strip();
                if (!line.isEmpty()) return boundedDiagnostic(line);
                offset = end + 1;
            }
        }
        return "";
    }

    private static String boundedDiagnostic(String value) {
        var text = new StringBuilder();
        int bytes = 0;
        for (int index = 0; index < value.length();) {
            int point = value.codePointAt(index); index += Character.charCount(point);
            if (Character.isISOControl(point)) { if (Character.isWhitespace(point)) point = ' '; else continue; }
            int width = point <= 0x7f ? 1 : point <= 0x7ff ? 2 : point <= 0xffff ? 3 : 4;
            if (bytes + width > DIAGNOSTIC_BYTES - 3) { text.append("..."); break; }
            text.appendCodePoint(point); bytes += width;
        }
        return text.toString();
    }

    private static Finding finding(Element bug, String pattern) {
        Element method = child(bug, "Method", "primary", "true");
        if (method == null) return null;
        String className = required(method.getAttribute("classname"), 1024);
        String methodName = required(method.getAttribute("name"), 512);
        String descriptor = required(method.getAttribute("signature"), 1024);
        Integer priority = integer(bug.getAttribute("priority"), 1);
        if (className == null || methodName == null || descriptor == null || priority == null || priority > 3) return null;

        Element location = child(bug, "SourceLine", "role", "SOURCE_LINE_DEREF");
        if (location == null) location = child(bug, "SourceLine", "primary", "true");
        String sourcePath = location == null ? null : required(location.getAttribute("sourcepath"), 1024);
        if (sourcePath != null && !SpotBugsAnalyzer.safeEntry(sourcePath)) sourcePath = null;
        Integer originalLine = location == null ? null : integer(location.getAttribute("start"), 1);
        Integer bytecodeOffset = location == null ? null : integer(location.getAttribute("startBytecode"), 0);
        String locationRole = preciseDereference(bug, location, className, bytecodeOffset) ? "SOURCE_LINE_DEREF" : null;
        Element messageNode = child(bug, "LongMessage", "", "");
        String message = messageNode == null ? pattern : messageNode.getTextContent().strip();
        if (message.isEmpty()) message = pattern;
        MethodIdentity sourceMethod = null;
        Integer nullSourceOffset = null;
        if ("NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE".equals(pattern)) {
            Element called = child(bug, "Method", "role", "METHOD_CALLED");
            if (called != null) {
                String owner = required(called.getAttribute("classname"), 1024), name = required(called.getAttribute("name"), 512), signature = required(called.getAttribute("signature"), 1024);
                if (owner != null && name != null && signature != null) sourceMethod = new MethodIdentity(owner, name, signature);
            }
            for (Node node = bug.getFirstChild(); node != null; node = node.getNextSibling()) {
                if (!(node instanceof Element line) || !"SourceLine".equals(line.getTagName()) || !className.equals(line.getAttribute("classname"))
                    || !"SOURCE_LINE_KNOWN_NULL".equals(line.getAttribute("role"))) continue;
                Integer start = integer(line.getAttribute("startBytecode"), 0), end = integer(line.getAttribute("endBytecode"), 0);
                if (start == null || !start.equals(end) || nullSourceOffset != null && !nullSourceOffset.equals(start)) { nullSourceOffset = null; break; }
                nullSourceOffset = start;
            }
        }
        return new Finding(pattern, className, methodName, descriptor, sourcePath, originalLine, bytecodeOffset, locationRole,
            message.substring(0, Math.min(message.length(), 4096)), priority, sourceMethod, nullSourceOffset);
    }

    private static boolean preciseDereference(Element bug, Element location, String className, Integer offset) {
        if (location == null || offset == null || !className.equals(location.getAttribute("classname"))
            || !offset.equals(integer(location.getAttribute("endBytecode"), 0))
            || !"SOURCE_LINE_DEREF".equals(location.getAttribute("role"))) return false;
        for (Node node = location.getNextSibling(); node != null; node = node.getNextSibling()) {
            if (node instanceof Element element && "SourceLine".equals(element.getTagName())
                && "SOURCE_LINE_DEREF".equals(element.getAttribute("role"))) return false;
        }
        return true;
    }

    private static Element child(Element parent, String name, String attribute, String value) {
        for (Node node = parent.getFirstChild(); node != null; node = node.getNextSibling()) {
            if (node instanceof Element element && name.equals(element.getTagName())
                && (attribute.isEmpty() || value.equals(element.getAttribute(attribute)))) return element;
        }
        return null;
    }

    private static String required(String value, int maxLength) {
        return value.isBlank() || value.length() > maxLength ? null : value;
    }

    private static Integer integer(String value, int minimum) {
        try {
            int parsed = Integer.parseInt(value);
            return parsed >= minimum ? parsed : null;
        } catch (NumberFormatException invalid) {
            return null;
        }
    }

    private static Result result(List<Finding> findings, List<String> diagnostics) {
        var bounded = new ArrayList<String>();
        for (String diagnostic : diagnostics) {
            if (bounded.size() == DIAGNOSTIC_LIMIT - 1 && diagnostics.size() > DIAGNOSTIC_LIMIT) {
                bounded.add("SpotBugs diagnostics truncated at 100 entries"); break;
            }
            if (bounded.size() == DIAGNOSTIC_LIMIT) break;
            bounded.add(boundedDiagnostic(diagnostic));
        }
        return new Result("spotbugs-v1", diagnostics.isEmpty() ? "complete" : "partial", TOOL_VERSION,
            List.copyOf(findings), List.copyOf(bounded));
    }

    record Result(String version, String status, String toolVersion, List<Finding> findings, List<String> diagnostics,
                  List<SuppressedFinding> suppressedFindings, @JsonInclude(JsonInclude.Include.NON_EMPTY) Map<String,Object> modelSummary) {
        Result(String version, String status, String toolVersion, List<Finding> findings, List<String> diagnostics) {
            this(version, status, toolVersion, findings, diagnostics, List.of(), Map.of());
        }
    }
    record SuppressedFinding(Finding finding, Map<String,Object> proof) {}
    record MethodIdentity(String className, String methodName, String methodDescriptor) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    record Finding(String pattern, String className, String methodName, String methodDescriptor, String sourcePath,
                   Integer originalLine, Integer bytecodeOffset, String locationRole, String message, int priority,
                   MethodIdentity returnValueSource, Integer nullSourceBytecodeOffset) {
        Finding(String pattern, String className, String methodName, String methodDescriptor, String sourcePath,
                Integer originalLine, Integer bytecodeOffset, String locationRole, String message, int priority) {
            this(pattern, className, methodName, methodDescriptor, sourcePath, originalLine, bytecodeOffset, locationRole, message, priority, null, null);
        }
    }
}
