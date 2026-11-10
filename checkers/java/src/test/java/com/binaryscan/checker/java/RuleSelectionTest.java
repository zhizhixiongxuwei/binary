package com.binaryscan.checker.java;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.context.WebServerApplicationContext;

import static org.junit.jupiter.api.Assertions.*;

final class RuleSelectionTest {
    private final ObjectMapper mapper = new ObjectMapper();
    private final CheckController controller = new CheckController(new JavaAnalyzer());

    @Test
    void publishesTheActualRegistryWithACompleteMetadataFingerprint() {
        var catalog = mapper.valueToTree(controller.rules());
        assertEquals("checker-v1", catalog.get("version").asText());
        assertEquals("java", catalog.get("language").asText()); assertEquals(14, catalog.get("rules").size());
        assertEquals(List.of("CWE-476"), RuleCatalog.rule("java-null-dereference").cwes());
        assertTrue(RuleCatalog.VERSION.matches("sha256:[0-9a-f]{64}")); assertEquals(RuleCatalog.IDS, JavaAnalyzer.RULE_IDS);
        for (var rule : RuleCatalog.RULES) {
            assertTrue(rule.default_enabled()); assertFalse(rule.name().isBlank()); assertFalse(rule.description().isBlank());
            assertFalse(rule.cwes().isEmpty()); assertFalse(rule.limitations().isEmpty()); assertEquals("java", rule.language());
        }
        var reversed = new ArrayList<>(RuleCatalog.RULES); Collections.reverse(reversed);
        assertEquals(RuleCatalog.VERSION, RuleCatalog.version(reversed));
        var old = reversed.getFirst();
        reversed.set(0, new RuleCatalog.Rule(old.id(), old.name()+"（修订）", old.description(), old.cwes(), old.severity(), old.language(), old.default_enabled(), old.limitations()));
        assertNotEquals(RuleCatalog.VERSION, RuleCatalog.version(reversed));
    }

    @Test
    void legacyRequestsRunAllRulesAndSelectionsAreCanonicalAndReturned() throws Exception {
        String source = """
            class Test {
                void run(String input) { Runtime.getRuntime().exec(input); new ProcessBuilder(input); }
                int size() { String text = null; return text.length(); }
            }
            """;
        var files = List.of(new Models.SourceFile("Test.java", source));
        var legacy = controller.check(new Models.CheckRequest("checker-v1", "project", "java", files, null, null));
        assertEquals(14, legacy.appliedRuleIds().size()); assertEquals(RuleCatalog.VERSION, legacy.catalogVersion());
        var selected = controller.check(new Models.CheckRequest("checker-v1", "project", "java", files,
            List.of("java-command-injection", "java-command-injection"), RuleCatalog.VERSION));
        assertEquals(List.of("java-command-injection"), selected.appliedRuleIds()); assertFalse(selected.findings().isEmpty());
        assertTrue(selected.findings().stream().allMatch(f -> f.ruleId().equals("java-command-injection")));
        var nullOnly = controller.check(new Models.CheckRequest("checker-v1", "project", "java", files,
            List.of("java-null-dereference"), RuleCatalog.VERSION));
        assertEquals(List.of("java-null-dereference"), nullOnly.appliedRuleIds());
        assertEquals(List.of("java-null-dereference"), nullOnly.findings().stream().map(Models.Finding::ruleId).toList());
        var omitted = mapper.readTree("{\"version\":\"checker-v1\",\"projectId\":\"p\",\"language\":\"java\",\"files\":[]}");
        assertEquals(14, controller.checkHttp(omitted).appliedRuleIds().size());
    }

    @Test
    void rejectsEmptyUnknownWrongLanguageStaleOrMalformedSelections() throws Exception {
        for (String suffix : List.of("\"ruleIds\":[]", "\"ruleIds\":[\"cwe-78-command\"]", "\"ruleIds\":[\"unknown\"]",
            "\"ruleIds\":null", "\"ruleIds\":[1]", "\"catalogVersion\":null", "\"catalogVersion\":\"checker-v1\"")) {
            var request = mapper.readTree("{\"version\":\"checker-v1\",\"projectId\":\"p\",\"language\":\"java\",\"files\":[],"+suffix+"}");
            assertThrows(RuntimeException.class, () -> controller.checkHttp(request), suffix);
        }
    }

    @Test
    void exposesCatalogAndValidatesSelectionThroughRealHTTP() throws Exception {
        try (var context = new SpringApplicationBuilder(JavaCheckerApplication.class)
            .properties("server.port=0", "spring.main.banner-mode=off", "logging.level.root=ERROR").run()) {
            int port = ((WebServerApplicationContext) context).getWebServer().getPort();
            var client = HttpClient.newHttpClient(); var base = "http://127.0.0.1:"+port;
            var catalog = client.send(HttpRequest.newBuilder(URI.create(base+"/v1/rules")).GET().build(), HttpResponse.BodyHandlers.ofString());
            assertEquals(200, catalog.statusCode()); assertEquals(RuleCatalog.VERSION, mapper.readTree(catalog.body()).get("catalogVersion").asText());
            for (String ids : List.of("[\"java-command-injection\"]", "[]", "null")) {
                String body = "{\"version\":\"checker-v1\",\"projectId\":\"p\",\"language\":\"java\",\"files\":[],\"ruleIds\":"+ids+"}";
                var response = client.send(HttpRequest.newBuilder(URI.create(base+"/v1/check")).header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
                assertEquals(ids.startsWith("[\"") ? 200 : 400, response.statusCode(), response.body());
                if (response.statusCode() == 200) assertEquals("java-command-injection", mapper.readTree(response.body()).get("appliedRuleIds").get(0).asText());
            }
        }
    }
}
