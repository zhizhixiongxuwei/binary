package com.binaryscan.checker.java;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.asm.*;
import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.asm.Opcodes.*;

final class FrameworkBytecodeVerifierTest {
    private static final String OBJECT_UTIL = "cn/hutool/core/util/ObjectUtil";
    private static final String YAML = "org/springframework/beans/factory/config/YamlPropertiesFactoryBean";
    private static final String COLLECTION_FACTORY = "org/springframework/core/CollectionFactory";
    private static final String PROPERTY_SOURCE = "org/springframework/core/env/PropertiesPropertySource";
    private static final String INPUT = "b".repeat(64);
    private static final Map<String,String> VERSIONS = Map.of("cn.hutool:hutool-core", "5.8.27", "org.springframework:spring-beans", "6.1.8", "org.springframework:spring-core", "6.1.8");
    @TempDir Path temp;

    @Test void suppressesOnlyExactNullSafeCallAndPreservesRawEvidence() throws IOException {
        Fixture fixture = hutool("business/ArbitraryName");
        var provider = provider(OBJECT_UTIL, 1);
        var input = input(fixture, Map.of(OBJECT_UTIL, provider));
        var result = verifier(Map.of(OBJECT_UTIL, provider)).review(raw(fixture.finding()), input, new FrameworkContracts(VERSIONS), INPUT);
        assertEquals(0, result.findings().size());
        assertEquals(1, result.suppressedFindings().size());
        var suppressed = result.suppressedFindings().getFirst();
        assertSame(fixture.finding(), suppressed.finding());
        assertEquals(FrameworkBytecodeVerifier.HUTOOL_MODEL, suppressed.proof().get("modelId"));
        assertEquals(fixture.finding().bytecodeOffset(), suppressed.proof().get("bytecodeOffset"));
        assertEquals(FrameworkContracts.sha256(fixture.bytes()), suppressed.proof().get("targetClassSha256"));
        assertEquals(FrameworkContracts.sha256(provider), suppressed.proof().get("providerClassSha256"));
        assertEquals(INPUT, suppressed.proof().get("inputSha256"));
        assertEquals(1, result.modelSummary().get("rawFindingCount"));
        assertEquals(1, result.modelSummary().get("suppressedFindingCount"));
        assertEquals(0, result.modelSummary().get("retainedFindingCount"));
    }

    @Test void changedProviderShadowWrongVersionAndUnboundInputCannotSuppress() throws IOException {
        Fixture fixture = hutool("sample/Consumer");
        byte[] trusted = provider(OBJECT_UTIL, 1), changed = provider(OBJECT_UTIL, 2);
        var verifier = verifier(Map.of(OBJECT_UTIL, trusted));
        assertRetained(verifier.review(raw(fixture.finding()), input(fixture, Map.of(OBJECT_UTIL, changed)), new FrameworkContracts(VERSIONS), INPUT));
        var shadow = new SpotBugsAnalyzer.PreparedInput(List.of(jar(Map.of(fixture.name(), fixture.bytes(), OBJECT_UTIL, changed))), List.of(jar(Map.of(OBJECT_UTIL, trusted))));
        assertRetained(verifier.review(raw(fixture.finding()), shadow, new FrameworkContracts(VERSIONS), INPUT));
        var alternate = new SpotBugsAnalyzer.PreparedInput(List.of(jar(Map.of(fixture.name(), fixture.bytes()))), List.of(jar(Map.of(OBJECT_UTIL, trusted, "META-INF/versions/21/" + OBJECT_UTIL, changed))));
        assertRetained(verifier.review(raw(fixture.finding()), alternate, new FrameworkContracts(VERSIONS), INPUT));
        var malformed = new SpotBugsAnalyzer.PreparedInput(List.of(jar(Map.of(fixture.name(), new byte[]{(byte) 0xca, (byte) 0xfe, (byte) 0xba, (byte) 0xbe, 0, 0, 0, 65}))), List.of(jar(Map.of(OBJECT_UTIL, trusted))));
        assertRetained(verifier.review(raw(fixture.finding()), malformed, new FrameworkContracts(VERSIONS), INPUT));
        assertRetained(verifier.review(raw(fixture.finding()), input(fixture, Map.of(OBJECT_UTIL, trusted)), new FrameworkContracts(Map.of("cn.hutool:hutool-core", "5.8.26")), INPUT));
        assertRetained(verifier.review(raw(fixture.finding()), input(fixture, Map.of(OBJECT_UTIL, trusted)), new FrameworkContracts(VERSIONS), ""));
        var wrongSite = new SpotBugsReport.Finding(fixture.finding().pattern(), fixture.finding().className(), "run", "(Ljava/lang/Object;)Z", null, null, 0, null, "test", 2);
        assertRetained(verifier.review(raw(wrongSite), input(fixture, Map.of(OBJECT_UTIL, trusted)), new FrameworkContracts(VERSIONS), INPUT));
    }

    @Test void freshConcreteYamlFactoryNeedsInitializationSourceIdentityAndSupportingClass() throws IOException {
        Fixture fixture = yaml(true, false, false);
        var providers = Map.of(YAML, provider(YAML, 1), COLLECTION_FACTORY, provider(COLLECTION_FACTORY, 1));
        var verifier = verifier(providers);
        var contracts = new FrameworkContracts(VERSIONS);
        var result = verifier.review(raw(fixture.finding()), input(fixture, providers), contracts, INPUT);
        assertEquals(1, result.suppressedFindings().size());
        var proof = result.suppressedFindings().getFirst().proof();
        assertEquals(FrameworkBytecodeVerifier.YAML_MODEL, proof.get("modelId"));
        assertEquals(fixture.finding().nullSourceBytecodeOffset(), proof.get("producerOffset"));
        assertEquals(FrameworkContracts.sha256(providers.get(COLLECTION_FACTORY)), proof.get("supportingClassSha256"));
        for (Fixture rejected : List.of(yaml(false, false, false), yaml(true, true, false), yaml(true, false, true))) {
            assertRetained(verifier.review(raw(rejected.finding()), input(rejected, providers), contracts, INPUT));
        }
        var original = fixture.finding();
        var unknownSource = new SpotBugsReport.Finding(original.pattern(), original.className(), original.methodName(), original.methodDescriptor(), null, null, original.bytecodeOffset(), null, "test", 2,
            new SpotBugsReport.MethodIdentity("business.OtherFactory", "getObject", "()Ljava/util/Properties;"), original.nullSourceBytecodeOffset());
        assertRetained(verifier.review(raw(unknownSource), input(fixture, providers), contracts, INPUT));
        var modified = new HashMap<>(providers); modified.put(COLLECTION_FACTORY, provider(COLLECTION_FACTORY, 2));
        assertRetained(verifier.review(raw(original), input(fixture, modified), contracts, INPUT));
    }

    @Test void unsupportedPatternAndUnprovedFindingsAreRetainedWithAccounting() throws IOException {
        Fixture fixture = hutool("sample/Consumer");
        var original = fixture.finding();
        var unsupported = new SpotBugsReport.Finding("NP_ALWAYS_NULL", original.className(), original.methodName(), original.methodDescriptor(), null, null, original.bytecodeOffset(), null, "test", 2);
        var result = new FrameworkBytecodeVerifier().review(raw(unsupported), input(fixture, Map.of()), new FrameworkContracts(VERSIONS), INPUT);
        assertRetained(result);
        assertEquals(1, result.modelSummary().get("rawFindingCount"));
        assertEquals(0, result.modelSummary().get("suppressedFindingCount"));
        assertEquals(1, result.modelSummary().get("retainedFindingCount"));
    }

    @Test @EnabledIfEnvironmentVariable(named = "BINARY_TEST_BYTECODE_LIBROOT", matches = ".+")
    void verifiesTheTwoRealWmsPatternsAgainstReleaseFingerprints() {
        Path lib = Path.of(System.getenv("BINARY_TEST_BYTECODE_LIBROOT"));
        var input = new SpotBugsAnalyzer.PreparedInput(List.of(lib.resolve("ruoyi-common-core-5.2.0.jar"), lib.resolve("ruoyi-common-encrypt-5.2.0.jar")),
            List.of(lib.resolve("hutool-core-5.8.27.jar"), lib.resolve("spring-beans-6.1.8.jar"), lib.resolve("spring-core-6.1.8.jar")));
        var crypto = new SpotBugsReport.Finding("NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE", "com.ruoyi.common.encrypt.filter.CryptoFilter", "getApiEncryptAnnotation", "(Ljakarta/servlet/http/HttpServletRequest;)Lcom/ruoyi/common/encrypt/annotation/ApiEncrypt;", null, null, 18, null, "test", 2);
        var yaml = new SpotBugsReport.Finding("NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE", "com.ruoyi.common.core.factory.YmlPropertySourceFactory", "createPropertySource", "(Ljava/lang/String;Lorg/springframework/core/io/support/EncodedResource;)Lorg/springframework/core/env/PropertySource;", null, null, 78, null, "test", 2,
            new SpotBugsReport.MethodIdentity(YAML.replace('/', '.'), "getObject", "()Ljava/util/Properties;"), 75);
        var result = new FrameworkBytecodeVerifier().review(raw(crypto, yaml), input, new FrameworkContracts(VERSIONS), INPUT);
        assertEquals(2, result.suppressedFindings().size(), result.toString());
        assertTrue(result.findings().isEmpty());
    }

    private static void assertRetained(SpotBugsReport.Result result) { assertEquals(1, result.findings().size(), result.toString()); assertTrue(result.suppressedFindings().isEmpty()); }
    private static SpotBugsReport.Result raw(SpotBugsReport.Finding... findings) { return new SpotBugsReport.Result("spotbugs-v1", "complete", "4.10.4", List.of(findings), List.of()); }
    private static FrameworkBytecodeVerifier verifier(Map<String,byte[]> classes) { var hashes = new HashMap<String,String>(); classes.forEach((name, bytes) -> hashes.put(name, FrameworkContracts.sha256(bytes))); return new FrameworkBytecodeVerifier(hashes); }
    private SpotBugsAnalyzer.PreparedInput input(Fixture fixture, Map<String,byte[]> providers) throws IOException { return new SpotBugsAnalyzer.PreparedInput(List.of(jar(Map.of(fixture.name(), fixture.bytes()))), List.of(jar(providers))); }
    private Path jar(Map<String,byte[]> classes) throws IOException {
        Path path = Files.createTempFile(temp, "classes-", ".jar");
        try (var output = new ZipOutputStream(Files.newOutputStream(path))) {
            for (var entry : classes.entrySet()) { output.putNextEntry(new ZipEntry(entry.getKey() + ".class")); output.write(entry.getValue()); output.closeEntry(); }
        }
        return path;
    }
    private static byte[] provider(String name, int variant) { var writer = writer(name); writer.visitField(ACC_PUBLIC | ACC_STATIC | ACC_FINAL, "fixtureVersion", "I", null, variant).visitEnd(); writer.visitEnd(); return writer.toByteArray(); }
    private static ClassWriter writer(String name) { var writer = new ClassWriter(ClassWriter.COMPUTE_MAXS); writer.visit(V21, ACC_PUBLIC, name, null, "java/lang/Object", null); return writer; }
    private static Fixture hutool(String name) {
        var writer = writer(name); var code = writer.visitMethod(ACC_PUBLIC | ACC_STATIC, "run", "(Ljava/lang/Object;)Z", null, null);
        code.visitCode(); code.visitVarInsn(ALOAD, 0); var site = new Label(); code.visitLabel(site); code.visitMethodInsn(INVOKESTATIC, OBJECT_UTIL, "isNotNull", "(Ljava/lang/Object;)Z", false); code.visitInsn(IRETURN); code.visitMaxs(0,0); code.visitEnd(); writer.visitEnd();
        var bytes = writer.toByteArray();
        return new Fixture(name, bytes, new SpotBugsReport.Finding("NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE", name.replace('/', '.'), "run", "(Ljava/lang/Object;)Z", null, null, site.getOffset(), null, "test", 2));
    }
    private static Fixture yaml(boolean initialize, boolean parameterFactory, boolean branchIntoAllocation) {
        String name = "unrelated/PropertyFactory", desc = "(Ljava/lang/String;L" + YAML + ";)Ljava/lang/Object;";
        var writer = writer(name); var code = writer.visitMethod(ACC_PUBLIC | ACC_STATIC, "run", desc, null, null); code.visitCode();
        var producer = new Label();
        if (branchIntoAllocation) { code.visitInsn(ICONST_0); code.visitJumpInsn(IFEQ, producer); }
        if (!parameterFactory) { code.visitTypeInsn(NEW, YAML); code.visitInsn(DUP); code.visitMethodInsn(INVOKESPECIAL, YAML, "<init>", "()V", false); code.visitVarInsn(ASTORE, 1); }
        if (initialize) { code.visitVarInsn(ALOAD, 1); code.visitMethodInsn(INVOKEVIRTUAL, YAML, "afterPropertiesSet", "()V", false); }
        code.visitTypeInsn(NEW, PROPERTY_SOURCE); code.visitInsn(DUP); code.visitVarInsn(ALOAD, 0); code.visitVarInsn(ALOAD, 1);
        code.visitLabel(producer); code.visitMethodInsn(INVOKEVIRTUAL, YAML, "getObject", "()Ljava/util/Properties;", false);
        var site = new Label(); code.visitLabel(site); code.visitMethodInsn(INVOKESPECIAL, PROPERTY_SOURCE, "<init>", "(Ljava/lang/String;Ljava/util/Properties;)V", false); code.visitInsn(ARETURN); code.visitMaxs(0,0); code.visitEnd(); writer.visitEnd();
        var bytes = writer.toByteArray();
        return new Fixture(name, bytes, new SpotBugsReport.Finding("NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE", name.replace('/', '.'), "run", desc, null, null, site.getOffset(), null, "test", 2,
            new SpotBugsReport.MethodIdentity(YAML.replace('/', '.'), "getObject", "()Ljava/util/Properties;"), producer.getOffset()));
    }
    private record Fixture(String name, byte[] bytes, SpotBugsReport.Finding finding) {}
}
