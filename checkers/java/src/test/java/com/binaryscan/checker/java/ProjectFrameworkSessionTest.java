package com.binaryscan.checker.java;

import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

final class ProjectFrameworkSessionTest {
    private Models.ProjectRequest request(Map<String,String> frameworks, String digest, String input) {
        return new Models.ProjectRequest("java-project-v1", "project", "run", "a".repeat(64),
            RuleCatalog.VERSION, List.of("java-null-dereference"), List.of(), frameworks, digest, input);
    }
    @Test void exposesProgressSnapshotsBeforeAndAfterAnalysis() {
        var controller = new ProjectCheckController(new JavaAnalyzer());
        try {
            var session = controller.create(request(Map.of(), null, null));
            assertEquals("uploading", controller.progress(session.sessionId()).phase());
            controller.analyze(session.sessionId());
            var completed = controller.progress(session.sessionId());
            assertEquals("java-project-v1", completed.version());
            assertEquals("completed", completed.phase());
            assertEquals("steps", completed.unit());
            assertEquals(completed.total(), completed.current());
        } finally { controller.close(); }
    }
    @Test void acceptsLargeAutomaticInventoryAndPinsItForIdempotentRetries() {
        var controller = new ProjectCheckController(new JavaAnalyzer());
        try {
            var frameworks = new TreeMap<String,String>();
            for (int i = 0; i < 37; i++) frameworks.put("example:module-"+i, "1.0");
            String digest = FrameworkContracts.digestJson(frameworks);
            var original = request(Map.copyOf(frameworks), digest, "b".repeat(64));
            var session = controller.create(original);
            assertEquals(session, controller.create(original));
            frameworks.put("example:module-0", "2.0");
            var changed = request(frameworks, FrameworkContracts.digestJson(frameworks), "b".repeat(64));
            assertEquals(409, assertThrows(ResponseStatusException.class, () -> controller.create(changed)).getStatusCode().value());
            assertEquals(409, assertThrows(ResponseStatusException.class, () -> controller.create(
                request(original.frameworks(), original.frameworksSha256(), "c".repeat(64)))).getStatusCode().value());
            controller.delete(session.sessionId());
        } finally { controller.close(); }
    }
    @Test void rejectsUnboundOrMismatchedFrameworkEvidence() {
        var controller = new ProjectCheckController(new JavaAnalyzer());
        try {
            var frameworks = Map.of("org.mybatis:mybatis", "3.5.16");
            String digest = FrameworkContracts.digestJson(frameworks);
            for (var invalid : List.of(request(frameworks, digest, null), request(frameworks, null, "b".repeat(64)),
                request(frameworks, "f".repeat(64), "b".repeat(64)), request(frameworks, digest, "not-a-hash"))) {
                assertEquals(400, assertThrows(ResponseStatusException.class, () -> controller.create(invalid)).getStatusCode().value());
            }
        } finally { controller.close(); }
    }
    @Test void retainsLegacySessionProtocolWithoutFrameworkAssumptions() {
        var controller = new ProjectCheckController(new JavaAnalyzer());
        try {
            var session = controller.create(new Models.ProjectRequest("java-project-v1", "project", "run", "a".repeat(64),
                RuleCatalog.VERSION, List.of("java-null-dereference"), List.of()));
            var result = controller.analyze(session.sessionId());
            assertEquals("framework-contracts-v1", result.modelSummary().get("frameworkContractVersion"));
            assertEquals(new FrameworkContracts(Map.of()).modelDigest(), result.modelSummary().get("frameworkContractDigest"));
        } finally { controller.close(); }
    }
}
