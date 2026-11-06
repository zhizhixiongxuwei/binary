package com.binaryscan.checker.c;

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
    private final CheckController controller = new CheckController(new CAnalyzer());

    @Test
    void publishesTheActualRegistryWithACompleteMetadataFingerprint() throws Exception {
        var catalog = mapper.valueToTree(controller.rules());
        assertEquals("checker-v1", catalog.get("version").asText());
        assertEquals("c", catalog.get("language").asText());
        assertEquals(15, catalog.get("rules").size());
        assertTrue(RuleCatalog.VERSION.matches("sha256:[0-9a-f]{64}"));
        assertEquals(RuleCatalog.IDS, CAnalyzer.RULE_IDS);
        for (var rule : RuleCatalog.RULES) {
            assertTrue(rule.default_enabled()); assertFalse(rule.name().isBlank());
            assertFalse(rule.description().isBlank()); assertFalse(rule.cwes().isEmpty());
            assertFalse(rule.limitations().isEmpty()); assertEquals("c", rule.language());
        }
        var reversed = new ArrayList<>(RuleCatalog.RULES); Collections.reverse(reversed);
        assertEquals(RuleCatalog.VERSION, RuleCatalog.version(reversed));
        var old = reversed.getFirst();
        reversed.set(0, new RuleCatalog.Rule(old.id(), old.name()+"（修订）", old.description(), old.cwes(), old.severity(), old.language(), old.default_enabled(), old.limitations()));
        assertNotEquals(RuleCatalog.VERSION, RuleCatalog.version(reversed));
    }

    @Test
    void legacyRequestsRunAllRulesWhileSelectionsAreCanonicalAndReturned() throws Exception {
        String source = "void run(char *input) { gets(input); system(input); }";
        var legacy = controller.check(new Models.CheckRequest("checker-v1", "project", "c", List.of(new Models.SourceFile("sample.c", source)), null, null));
        assertEquals(15, legacy.appliedRuleIds().size()); assertEquals(RuleCatalog.VERSION, legacy.catalogVersion());
        var selected = controller.check(new Models.CheckRequest("checker-v1", "project", "c", List.of(new Models.SourceFile("sample.c", source)),
            List.of("cwe-78-command", "cwe-78-command"), RuleCatalog.VERSION));
        assertEquals(List.of("cwe-78-command"), selected.appliedRuleIds());
        assertFalse(selected.findings().isEmpty()); assertTrue(selected.findings().stream().allMatch(f -> f.ruleId().equals("cwe-78-command")));
        var omitted = mapper.readTree("{\"version\":\"checker-v1\",\"projectId\":\"p\",\"language\":\"c\",\"files\":[]}");
        assertEquals(15, controller.checkHttp(omitted).appliedRuleIds().size());
    }

    @Test
    void rejectsEmptyUnknownWrongLanguageStaleOrMalformedSelections() throws Exception {
        for (String suffix : List.of("\"ruleIds\":[]", "\"ruleIds\":[\"java-command-injection\"]", "\"ruleIds\":[\"unknown\"]",
            "\"ruleIds\":null", "\"ruleIds\":[1]", "\"catalogVersion\":null", "\"catalogVersion\":\"checker-v1\"")) {
            var request = mapper.readTree("{\"version\":\"checker-v1\",\"projectId\":\"p\",\"language\":\"c\",\"files\":[],"+suffix+"}");
            assertThrows(RuntimeException.class, () -> controller.checkHttp(request), suffix);
        }
    }

    @Test
    void exposesCatalogAndValidatesSelectionThroughRealHTTP() throws Exception {
        try (var context = new SpringApplicationBuilder(CCheckerApplication.class)
            .properties("server.port=0", "spring.main.banner-mode=off", "logging.level.root=ERROR").run()) {
            int port = ((WebServerApplicationContext) context).getWebServer().getPort();
            var client = HttpClient.newHttpClient();
            var base = "http://127.0.0.1:"+port;
            var catalog = client.send(HttpRequest.newBuilder(URI.create(base+"/v1/rules")).GET().build(), HttpResponse.BodyHandlers.ofString());
            assertEquals(200, catalog.statusCode()); assertEquals(RuleCatalog.VERSION, mapper.readTree(catalog.body()).get("catalogVersion").asText());
            for (String ids : List.of("[\"cwe-78-command\"]", "[]", "null")) {
                String body = "{\"version\":\"checker-v1\",\"projectId\":\"p\",\"language\":\"c\",\"files\":[],\"ruleIds\":"+ids+"}";
                var response = client.send(HttpRequest.newBuilder(URI.create(base+"/v1/check")).header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
                assertEquals(ids.startsWith("[\"") ? 200 : 400, response.statusCode(), response.body());
                if (response.statusCode() == 200) assertEquals("cwe-78-command", mapper.readTree(response.body()).get("appliedRuleIds").get(0).asText());
            }
        }
    }
}
