package com.binaryscan.checker.java;

import org.springframework.asm.*;
import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import java.util.zip.ZipFile;
import static org.springframework.asm.Opcodes.*;

/** Conservative proof review. Unproved findings remain visible with their raw evidence. */
final class FrameworkBytecodeVerifier {
    static final String HUTOOL_MODEL = "hutool-5.8.27-null-predicate";
    static final String YAML_MODEL = "spring-6.1.8-yaml-properties-concrete";
    private static final String OBJECT_UTIL = "cn/hutool/core/util/ObjectUtil";
    private static final String YAML = "org/springframework/beans/factory/config/YamlPropertiesFactoryBean";
    private static final String COLLECTION_FACTORY = "org/springframework/core/CollectionFactory";
    private static final String PROPERTY_SOURCE = "org/springframework/core/env/PropertiesPropertySource";
    // Class fingerprints independently checked against official Maven Central
    // releases. Version metadata by itself does not authenticate a provider.
    private static final Map<String,String> RELEASE_CLASSES = Map.of(
        OBJECT_UTIL, "06975d9cf0d3ba7f6dda5c64883f92290ad898ade9f8045c15e54e1839f9289d",
        YAML, "60ceeb140973ec6f58721e99caed246aab5fd32c51112c9f9b72e75a0b2554bc",
        COLLECTION_FACTORY, "0cd9b7eb4d4e20e24edbee11992ae02b2a9e21a596d431b26ab8e12ac3c82f01");
    private final Map<String,String> releaseClasses;
    FrameworkBytecodeVerifier() { this(RELEASE_CLASSES); }
    // Package-private injection keeps portable tests independent of a local
    // Maven cache. Production always uses the immutable release table above.
    FrameworkBytecodeVerifier(Map<String,String> releaseClasses) { this.releaseClasses = Map.copyOf(releaseClasses); }

    SpotBugsReport.Result review(SpotBugsReport.Result raw, SpotBugsAnalyzer.PreparedInput input, FrameworkContracts contracts, String inputSha256) {
        var retained = new ArrayList<SpotBugsReport.Finding>();
        var suppressed = new ArrayList<SpotBugsReport.SuppressedFinding>();
        var universe = new Universe(input);
        int checked = 0;
        boolean budget = false;
        long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(15);
        for (var finding : raw.findings()) {
            Map<String,Object> proof = null;
            if (checked++ < 256 && System.nanoTime() < deadline && inputSha256 != null && inputSha256.matches("[a-f0-9]{64}")) {
                try { proof = prove(finding, universe, contracts, inputSha256); }
                catch (IOException | RuntimeException ignored) { /* Retain on absent/ambiguous/unreadable evidence; never swallow VM errors. */ }
            } else budget = true;
            if (proof == null) retained.add(finding);
            else suppressed.add(new SpotBugsReport.SuppressedFinding(finding, proof));
        }
        var summary = new LinkedHashMap<String,Object>();
        summary.put("version", contracts.version()); summary.put("modelDigest", contracts.modelDigest());
        summary.put("frameworksSha256", contracts.frameworksSha256()); summary.put("frameworks", contracts.frameworks());
        if (inputSha256 != null && !inputSha256.isEmpty()) summary.put("inputSha256", inputSha256);
        summary.put("rawFindingCount", raw.findings().size()); summary.put("suppressedFindingCount", suppressed.size()); summary.put("retainedFindingCount", retained.size());
        if (budget || universe.budgetReached) summary.put("reviewBudgetReached", true);
        return new SpotBugsReport.Result(raw.version(), raw.status(), raw.toolVersion(), List.copyOf(retained), raw.diagnostics(), List.copyOf(suppressed), Map.copyOf(summary));
    }

    private Map<String,Object> prove(SpotBugsReport.Finding finding, Universe universe, FrameworkContracts contracts, String inputSha) throws IOException {
        if (!finding.pattern().equals("NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE") || finding.bytecodeOffset() == null) return null;
        ClassBytes target = universe.target(finding.className().replace('.', '/'));
        if (target == null) return null;
        MethodCode method = MethodCode.read(target.bytes, finding.methodName(), finding.methodDescriptor());
        int index = method.index(finding.bytecodeOffset());
        if (index < 0) return null;
        Insn site = method.instructions.get(index);
        String model = null, provider = null;
        ClassBytes supporting = null;
        int producer = -1;
        if (contracts.supports("cn.hutool:hutool-core") && site.opcode == INVOKESTATIC && site.owner.equals(OBJECT_UTIL)
            && Set.of("isNull", "isNotNull").contains(site.name) && site.descriptor.equals("(Ljava/lang/Object;)Z")) {
            model = HUTOOL_MODEL; provider = OBJECT_UTIL;
        } else if (contracts.exact("org.springframework:spring-beans", "6.1.8") && contracts.exact("org.springframework:spring-core", "6.1.8")
            && site.opcode == INVOKESPECIAL && site.owner.equals(PROPERTY_SOURCE) && site.name.equals("<init>")
            && site.descriptor.equals("(Ljava/lang/String;Ljava/util/Properties;)V") && index >= 2) {
            var source = finding.returnValueSource();
            Insn produced = method.instructions.get(index - 1), loaded = method.instructions.get(index - 2);
            if (source == null || !source.className().equals(YAML.replace('/', '.')) || !source.methodName().equals("getObject")
                || !source.methodDescriptor().equals("()Ljava/util/Properties;") || finding.nullSourceBytecodeOffset() == null
                || finding.nullSourceBytecodeOffset() != produced.offset || produced.opcode != INVOKEVIRTUAL || !produced.owner.equals(YAML)
                || !produced.name.equals("getObject") || !produced.descriptor.equals("()Ljava/util/Properties;") || loaded.opcode != ALOAD
                || !freshInitializedFactory(method, index - 1, loaded.variable)) return null;
            supporting = universe.provider(COLLECTION_FACTORY);
            if (!verified(COLLECTION_FACTORY, supporting)) return null;
            model = YAML_MODEL; provider = YAML; producer = produced.offset;
        }
        if (model == null) return null;
        ClassBytes library = universe.provider(provider);
        if (!verified(provider, library)) return null;
        var proof = new LinkedHashMap<String,Object>();
        proof.put("modelId", model); proof.put("modelVersion", contracts.version()); proof.put("modelDigest", contracts.modelDigest());
        proof.put("frameworksSha256", contracts.frameworksSha256()); proof.put("inputSha256", inputSha);
        proof.put("targetClassSha256", target.digest); proof.put("methodDescriptor", finding.methodDescriptor()); proof.put("bytecodeOffset", finding.bytecodeOffset());
        proof.put("callOwner", site.owner.replace('/', '.')); proof.put("callName", site.name); proof.put("callDescriptor", site.descriptor);
        proof.put("providerClassName", provider.replace('/', '.')); proof.put("providerClassSha256", library.digest);
        if (supporting != null) {
            proof.put("supportingClassName", COLLECTION_FACTORY.replace('/', '.')); proof.put("supportingClassSha256", supporting.digest);
            proof.put("producerOwner", YAML.replace('/', '.')); proof.put("producerName", "getObject"); proof.put("producerDescriptor", "()Ljava/util/Properties;"); proof.put("producerOffset", producer);
        }
        return Map.copyOf(proof);
    }

    private boolean verified(String name, ClassBytes bytes) { return bytes != null && bytes.digest.equals(releaseClasses.get(name)); }

    private static boolean freshInitializedFactory(MethodCode code, int producerIndex, int slot) {
        int stored = -1;
        for (int index = producerIndex - 1; index >= 0; index--) { var instruction = code.instructions.get(index); if (instruction.opcode == ASTORE && instruction.variable == slot) { stored = index; break; } }
        if (stored < 3) return false;
        Insn init = code.instructions.get(stored - 1), dup = code.instructions.get(stored - 2), allocation = code.instructions.get(stored - 3);
        if (init.opcode != INVOKESPECIAL || !init.owner.equals(YAML) || !init.name.equals("<init>") || !init.descriptor.equals("()V") || dup.opcode != DUP
            || allocation.opcode != NEW || !allocation.owner.equals(YAML)) return false;
        int start = allocation.offset, end = code.instructions.get(producerIndex).offset;
        for (Insn instruction : code.instructions) if (instruction.target != null) {
            Integer target = code.labels.get(instruction.target);
            if (target == null || target > start && target <= end) return false;
        }
        for (Label handler : code.handlers) { Integer target = code.labels.get(handler); if (target == null || target > start && target <= end) return false; }
        var stack = new ArrayList<Boolean>(); boolean initialized = false;
        try {
            for (int index = stored + 1; index <= producerIndex; index++) {
                Insn instruction = code.instructions.get(index);
                switch (instruction.opcode) {
                    case NOP -> { }
                    case ALOAD -> stack.add(instruction.variable == slot);
                    case ILOAD, LLOAD, FLOAD, DLOAD, ACONST_NULL, ICONST_M1, ICONST_0, ICONST_1, ICONST_2, ICONST_3, ICONST_4, ICONST_5, BIPUSH, SIPUSH, LDC, NEW -> stack.add(false);
                    case DUP -> stack.add(stack.getLast());
                    case CHECKCAST -> { }
                    case ANEWARRAY -> { if (pop(stack)) return false; stack.add(false); }
                    case AASTORE -> { if (pop(stack) || pop(stack) || pop(stack)) return false; }
                    case ASTORE, ISTORE, LSTORE, FSTORE, DSTORE, POP -> { if (pop(stack) || instruction.opcode == ASTORE && instruction.variable == slot) return false; }
                    case INVOKESTATIC, INVOKEVIRTUAL, INVOKEINTERFACE, INVOKESPECIAL -> {
                        for (Type ignored : Type.getArgumentTypes(instruction.descriptor)) if (pop(stack)) return false; // factory must never escape as an argument
                        boolean receiver = instruction.opcode != INVOKESTATIC && pop(stack);
                        if (receiver) {
                            if (!instruction.owner.equals(YAML)) return false;
                            if (instruction.name.equals("afterPropertiesSet") && instruction.descriptor.equals("()V")) initialized = true;
                            else if (!(instruction.name.equals("setResources") && instruction.descriptor.equals("([Lorg/springframework/core/io/Resource;)V"))
                                && !(index == producerIndex && initialized && instruction.name.equals("getObject") && instruction.descriptor.equals("()Ljava/util/Properties;"))) return false;
                        } else if (index == producerIndex) return false;
                        if (Type.getReturnType(instruction.descriptor).getSort() != Type.VOID) stack.add(false);
                    }
                    default -> { return false; }
                }
            }
            return initialized;
        } catch (IndexOutOfBoundsException invalid) { return false; }
    }
    private static boolean pop(ArrayList<Boolean> stack) { return stack.removeLast(); }

    private record ClassBytes(byte[] bytes, String digest) {}
    private static final class Universe {
        final List<Path> targets, all;
        final Map<String,ClassBytes> targetCache = new HashMap<>(), providerCache = new HashMap<>();
        long remaining = 32L << 20; boolean budgetReached;
        Universe(SpotBugsAnalyzer.PreparedInput input) { targets = input.targets(); all = new ArrayList<>(targets); all.addAll(input.dependencies()); }
        ClassBytes target(String name) throws IOException { return read(name, targets, targetCache); }
        ClassBytes provider(String name) throws IOException { return read(name, all, providerCache); }
        ClassBytes read(String name, List<Path> archives, Map<String,ClassBytes> cache) throws IOException {
            if (cache.containsKey(name)) return cache.get(name);
            if (cache.size() >= 256) { budgetReached = true; return null; }
            ClassBytes found = null;
            for (Path archive : archives) {
                byte[] bytes = null;
                if (archive.getFileName().toString().endsWith(".class")) {
                    long size = Files.size(archive); if (size > (4L << 20) || size > remaining) { budgetReached = true; return null; }
                    byte[] candidate = Files.readAllBytes(archive); remaining -= candidate.length;
                    if (new ClassReader(candidate).getClassName().equals(name)) bytes = candidate;
                } else try (var jar = new ZipFile(archive.toFile())) {
                    // Normalized bundles have already selected Java 21 classes.
                    // A legacy raw JAR with an alternate provider cannot supply
                    // an unambiguous proof from only its base entry.
                    for (int version = 9; version <= 21; version++) if (jar.getEntry("META-INF/versions/" + version + "/" + name + ".class") != null) return null;
                    var entry = jar.getEntry(name + ".class");
                    if (entry == null) continue;
                    if (entry.getSize() < 0 || entry.getSize() > (4L << 20) || entry.getSize() > remaining) { budgetReached = true; return null; }
                    try (var source = jar.getInputStream(entry)) { bytes = source.readNBytes((int) Math.min(remaining, 4L << 20) + 1); }
                    remaining -= bytes.length;
                    if (bytes.length != entry.getSize()) return null;
                }
                if (bytes == null) continue;
                String digest = FrameworkContracts.sha256(bytes);
                if (found != null && !found.digest.equals(digest)) { cache.put(name, null); return null; }
                if (!new ClassReader(bytes).getClassName().equals(name)) return null;
                found = new ClassBytes(bytes, digest);
            }
            cache.put(name, found); return found;
        }
    }

    private record Insn(int offset, int opcode, int variable, String owner, String name, String descriptor, Label target) {}
    private static final class MethodCode extends MethodVisitor {
        final OffsetReader reader; final List<Insn> instructions = new ArrayList<>();
        final Map<Label,Integer> labels = new IdentityHashMap<>(); final List<Label> handlers = new ArrayList<>();
        MethodCode(OffsetReader reader) { super(ASM9); this.reader = reader; }
        static MethodCode read(byte[] bytes, String method, String descriptor) {
            var reader = new OffsetReader(bytes); final MethodCode[] result = {new MethodCode(reader)}; final int[] matches = {0};
            reader.accept(new ClassVisitor(ASM9) {
                @Override public MethodVisitor visitMethod(int access, String name, String desc, String signature, String[] exceptions) {
                    boolean matched = name.equals(method) && desc.equals(descriptor);
                    if (matched) matches[0]++;
                    reader.active = matched ? result[0] : null; return reader.active;
                }
            }, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
            if (matches[0] != 1) result[0].instructions.clear();
            return result[0];
        }
        int index(int offset) { for (int i = 0; i < instructions.size(); i++) if (instructions.get(i).offset == offset) return i; return -1; }
        void add(int opcode, int variable, String owner, String name, String descriptor, Label target) { instructions.add(new Insn(reader.offset, opcode, variable, owner, name, descriptor, target)); }
        @Override public void visitInsn(int opcode) { add(opcode, -1, "", "", "", null); }
        @Override public void visitIntInsn(int opcode, int operand) { visitInsn(opcode); }
        @Override public void visitVarInsn(int opcode, int variable) { add(opcode, variable, "", "", "", null); }
        @Override public void visitTypeInsn(int opcode, String type) { add(opcode, -1, type, "", "", null); }
        @Override public void visitFieldInsn(int opcode, String owner, String name, String descriptor) { add(opcode, -1, owner, name, descriptor, null); }
        @Override public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean isInterface) { add(opcode, -1, owner, name, descriptor, null); }
        @Override public void visitInvokeDynamicInsn(String name, String descriptor, Handle bootstrap, Object... arguments) { add(INVOKEDYNAMIC, -1, "", name, descriptor, null); }
        @Override public void visitJumpInsn(int opcode, Label label) { add(opcode, -1, "", "", "", label); }
        // ClassReader calls the offset hook *before* this instruction's label.
        @Override public void visitLabel(Label label) { labels.put(label, reader.offset); }
        @Override public void visitLdcInsn(Object value) { visitInsn(LDC); }
        @Override public void visitIincInsn(int variable, int increment) { visitInsn(IINC); }
        @Override public void visitTableSwitchInsn(int min, int max, Label dflt, Label... labels) { visitJumpInsn(TABLESWITCH, dflt); for (Label label : labels) visitJumpInsn(TABLESWITCH, label); }
        @Override public void visitLookupSwitchInsn(Label dflt, int[] keys, Label[] labels) { visitJumpInsn(LOOKUPSWITCH, dflt); for (Label label : labels) visitJumpInsn(LOOKUPSWITCH, label); }
        @Override public void visitMultiANewArrayInsn(String descriptor, int dimensions) { visitInsn(MULTIANEWARRAY); }
        @Override public void visitTryCatchBlock(Label start, Label end, Label handler, String type) { handlers.add(handler); }
    }
    private static final class OffsetReader extends ClassReader {
        int offset; MethodCode active;
        OffsetReader(byte[] bytes) { super(bytes); }
        @Override protected void readBytecodeInstructionOffset(int offset) {
            this.offset = offset;
        }
    }
}
