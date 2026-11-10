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

/** Parses only the null dereference evidence emitted by the pinned SpotBugs release. */
final class SpotBugsReport {
    private static final String TOOL_VERSION = "4.10.4";
    private static final int FINDING_LIMIT = 10_000;
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
        return new Finding(pattern, className, methodName, descriptor, sourcePath, originalLine, bytecodeOffset, locationRole,
            message.substring(0, Math.min(message.length(), 4096)), priority);
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
        return new Result("spotbugs-v1", diagnostics.isEmpty() ? "complete" : "partial", TOOL_VERSION,
            List.copyOf(findings), List.copyOf(diagnostics));
    }

    record Result(String version, String status, String toolVersion, List<Finding> findings, List<String> diagnostics) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    record Finding(String pattern, String className, String methodName, String methodDescriptor, String sourcePath,
                   Integer originalLine, Integer bytecodeOffset, String locationRole, String message, int priority) {}
}
