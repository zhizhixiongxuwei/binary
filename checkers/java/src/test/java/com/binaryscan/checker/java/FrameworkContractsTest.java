package com.binaryscan.checker.java;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

final class FrameworkContractsTest {
    @Test void bindsContractsToCoordinatesVersionsAndResolvedOwners() {
        var unknown = new FrameworkContracts(Map.of());
        var known = new FrameworkContracts(Map.of("cn.hutool:hutool-core", "5.8.27", "org.mybatis:mybatis", "3.5.16",
            "com.baomidou:mybatis-plus-core", "3.5.6", "io.github.linpeilie:mapstruct-plus", "1.3.6"));
        assertEquals(FrameworkContracts.PredicateKind.NONE, unknown.predicate("cn.hutool.core.util.ObjectUtil", "isNotNull", 1));
        assertEquals(FrameworkContracts.PredicateKind.NOT_EMPTY, known.predicate("cn.hutool.core.util.ObjectUtil", "isNotNull", 1));
        assertEquals(FrameworkContracts.PredicateKind.EMPTY, known.predicate("cn.hutool.core.util.ObjectUtil", "isNull", 1));
        assertEquals(FrameworkContracts.PredicateKind.NULL, known.predicate("java.util.Objects", "isNull", 1));
        assertEquals(FrameworkContracts.PredicateKind.NOT_NULL, known.predicate("java.util.Objects", "nonNull", 1));
        assertEquals(FrameworkContracts.PredicateKind.NONE, known.predicate("business.ObjectUtil", "isNotNull", 1));
        assertEquals(FrameworkContracts.PredicateKind.NONE, known.predicate("cn.hutool.core.util.ObjectUtil", "isNotNull", 2));
        assertEquals(FrameworkContracts.ReturnKind.NULLABLE, known.method("com.baomidou.mybatisplus.core.mapper.BaseMapper", "selectById", List.of("java.lang.Long"), "business.Entity").kind());
        assertEquals(FrameworkContracts.ReturnKind.NORMAL_NON_NULL, known.mapperReturn("java.util.List<business.Entity>", List.of()).kind());
        assertEquals(FrameworkContracts.ReturnKind.NULLABLE, known.mapperReturn("business.Entity", List.of()).kind());
        assertEquals(FrameworkContracts.ReturnKind.NULLABLE, known.mapperReturn("java.util.Map<java.lang.String,java.lang.Object>", List.of()).kind());
        assertEquals(FrameworkContracts.ReturnKind.UNKNOWN, unknown.mapperReturn("java.util.List<business.Entity>", List.of()).kind());
        assertEquals(FrameworkContracts.ReturnKind.NORMAL_NON_NULL, known.mapperReturn("com.baomidou.mybatisplus.core.metadata.IPage<business.Entity>", List.of("com.baomidou.mybatisplus.core.metadata.IPage<business.Entity>")).kind());
        assertEquals(FrameworkContracts.ReturnKind.NULLABLE, known.mapperReturn("com.baomidou.mybatisplus.core.metadata.IPage<business.Entity>", List.of()).kind());
        assertEquals(FrameworkContracts.ReturnKind.UNKNOWN, known.method("io.github.linpeilie.Converter", "convert", List.of("business.Entity", "java.lang.Class"), "business.Dto").kind());
        assertEquals(FrameworkContracts.ReturnKind.NORMAL_NON_NULL, known.method("io.github.linpeilie.Converter", "convert", List.of("java.util.List<business.Entity>", "java.lang.Class"), "java.util.List<business.Dto>").kind());
        assertEquals(FrameworkContracts.ReturnKind.NULLABLE, known.method("io.github.linpeilie.Converter", "convert", List.of("java.util.Map", "java.lang.Class"), "business.Dto").kind());
        assertEquals(FrameworkContracts.ReturnKind.UNKNOWN, known.method("cn.hutool.core.util.ObjectUtil", "defaultIfNull", List.of("java.lang.Object", "java.lang.Object"), "java.lang.Object").kind());
    }

    @Test void unknownOrConflictingVersionsDisableThirdPartyModels() {
        for (var versions : List.of(Map.of("cn.hutool:hutool-core", "5.8.26"),
            Map.of("cn.hutool:hutool-core", "5.8.27", "cn.hutool:hutool-all", "5.8.26"))) {
            assertFalse(new FrameworkContracts(versions).supports("cn.hutool:hutool-core"));
        }
        var all = new FrameworkContracts(Map.of("cn.hutool:hutool-all", "5.8.27"));
        assertTrue(all.supports("cn.hutool:hutool-core"));
        assertEquals("5.8.27", all.dependencyVersion("hutool-5.8.27-null-predicate"));
        assertEquals(FrameworkContracts.ReturnKind.NORMAL_NON_NULL, all.method("java.util.Collections", "emptyList", List.of(), "java.util.List").kind());
    }

    @Test void canonicalSnapshotDigestIsStableAndVersionBound() throws Exception {
        var first = new LinkedHashMap<String,String>(); first.put("z:last", "2"); first.put("a:first", "1");
        var second = new TreeMap<>(first);
        var contracts = new FrameworkContracts(first);
        assertEquals(FrameworkContracts.digestJson(second), contracts.frameworksSha256());
        assertEquals(FrameworkContracts.sha256((FrameworkContracts.VERSION + "\n" + contracts.frameworksSha256()).getBytes(java.nio.charset.StandardCharsets.UTF_8)), contracts.modelDigest());
        second.put("a:first", "2");
        assertNotEquals(new FrameworkContracts(second).modelDigest(), contracts.modelDigest());
        assertEquals(2, contracts.frameworks().size());
        assertThrows(UnsupportedOperationException.class, () -> contracts.frameworks().put("x:y", "1"));
        assertEquals(contracts.frameworksSha256(), BytecodeCheckController.contracts(new ObjectMapper().writeValueAsString(first), contracts.frameworksSha256(), "b".repeat(64)).frameworksSha256());
    }

    @Test void bytecodeMetadataRejectsCoercionAmbiguityAndMissingBinding() {
        assertNull(BytecodeCheckController.contracts(null, null, null));
        String empty = FrameworkContracts.digestJson(Map.of());
        String scalar = FrameworkContracts.digestJson(Map.of("example:artifact", "1"));
        for (String json : List.of("null", "[]", "{\"example:artifact\":1}", "{\"example:artifact\":\"1\",\"example:artifact\":\"1\"}", "{}{}", " ".repeat(8193))) {
            assertEquals(400, assertThrows(ResponseStatusException.class, () -> BytecodeCheckController.contracts(json, scalar, "b".repeat(64))).getStatusCode().value());
        }
        assertThrows(ResponseStatusException.class, () -> BytecodeCheckController.contracts("{}", empty, null));
        assertThrows(ResponseStatusException.class, () -> BytecodeCheckController.contracts("{}", "f".repeat(64), "b".repeat(64)));
        assertThrows(ResponseStatusException.class, () -> BytecodeCheckController.contracts("{}", empty, "B".repeat(64)));
    }

    @Test void legacyBytecodeResultDoesNotInventAModelSummary() throws Exception {
        var json = new ObjectMapper().readTree(new ObjectMapper().writeValueAsString(SpotBugsReport.partial("test")));
        assertFalse(json.has("modelSummary"));
        assertEquals(0, json.get("suppressedFindings").size());
    }
}
