import org.jetbrains.java.decompiler.code.Instruction;
import org.jetbrains.java.decompiler.main.DecompilerContext;
import org.jetbrains.java.decompiler.main.Fernflower;
import org.jetbrains.java.decompiler.main.collectors.BytecodeSourceMapper;
import org.jetbrains.java.decompiler.main.decompiler.DirectoryResultSaver;
import org.jetbrains.java.decompiler.main.decompiler.PrintStreamLogger;
import org.jetbrains.java.decompiler.main.extern.IFernflowerPreferences;
import org.jetbrains.java.decompiler.struct.StructClass;
import org.jetbrains.java.decompiler.struct.StructMethod;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.jar.JarFile;

import static org.jetbrains.java.decompiler.code.CodeConstants.*;

/** Writes normal Vineflower folder output plus a private mapping for JVM dereferences. */
public final class ExportVineflowerSource {
    private static final String HEADER = "binaryscan-vineflower-map-v1";
    private static final int MAX_ROWS = 200_000;
    private static final int MAX_ROW_BYTES = 16 << 10;
    private static final int MAX_BYTES = 16 << 20;

    public static void main(String[] args) throws IOException {
        if (args.length != 3) throw new IllegalArgumentException("expected input, output directory and mapping file");
        File input = new File(args[0]);
        File output = new File(args[1]);
        boolean standalone = input.getName().endsWith(".class");
        Mapping mapping = new Mapping();
        MapperAccess access = MapperAccess.open();
        if (access == null || (!standalone && ambiguousArchive(input))) mapping.disable();
        var decompiler = new MappingDecompiler(output, standalone, mapping, access);
        try {
            decompiler.addSource(input);
            decompiler.decompileContext();
        } finally {
            decompiler.clearContext();
        }
        mapping.write(Path.of(args[2]));
    }

    private static boolean ambiguousArchive(File input) {
        try (JarFile jar = new JarFile(input, false)) {
            if (jar.isMultiRelease() || jar.size() > MAX_ROWS) return true;
            var classEntries = new HashSet<String>();
            var entries = jar.entries();
            while (entries.hasMoreElements()) {
                String name = entries.nextElement().getName();
                if (name.endsWith(".class") && (name.startsWith("META-INF/versions/") || !classEntries.add(name))) {
                    return true;
                }
            }
            return false;
        } catch (IOException failure) {
            return true;
        }
    }

    private static final class MappingDecompiler extends Fernflower {
        private final boolean standalone;
        private final Mapping mapping;
        private final MapperAccess access;
        private final Set<String> classes = new HashSet<>();
        private final Map<StructClass, String> outputPaths = new ConcurrentHashMap<>();

        MappingDecompiler(File output, boolean standalone, Mapping mapping, MapperAccess access) {
            super(new SafeDirectorySaver(output), Map.of(IFernflowerPreferences.BYTECODE_SOURCE_MAPPING, "1",
                IFernflowerPreferences.LOG_LEVEL, "ERROR"), new PrintStreamLogger(System.out));
            this.standalone = standalone;
            this.mapping = mapping;
            this.access = access;
        }

        @Override
        public String getClassEntryName(StructClass type, String inputEntry) {
            String entry = super.getClassEntryName(type, inputEntry);
            if (!mapping.disabled) {
                if (classes.size() == MAX_ROWS || !classes.add(type.qualifiedName)) mapping.disable();
                else if (entry != null && entry.endsWith(".java") && safePath(entry)) {
                    outputPaths.put(type, standalone ? entry.substring(entry.lastIndexOf('/') + 1) : entry);
                }
            }
            return entry;
        }

        @Override
        public String getClassContent(StructClass type) {
            String content = super.getClassContent(type);
            String outputPath = outputPaths.remove(type);
            if (!mapping.disabled && outputPath != null && content != null
                && !content.startsWith("$ VF:") && !content.startsWith("/*\n$VF:") && !content.startsWith("/*\r\n$VF:")) {
                try {
                    capture(outputPath, DecompilerContext.getBytecodeSourceMapper());
                } catch (ReflectiveOperationException | IOException | RuntimeException failure) {
                    mapping.disable();
                }
            }
            return content;
        }

        private void capture(String path, BytecodeSourceMapper mapper) throws ReflectiveOperationException, IOException {
            int lineOffset = access.lineOffset.getInt(mapper) + 1;
            for (var classEntry : access.classes(mapper).entrySet()) {
                if (mapping.disabled) return;
                StructClass owner = DecompilerContext.getStructContext().getClass(classEntry.getKey());
                if (owner == null || !owner.isOwn()) continue;
                for (var methodEntry : classEntry.getValue().entrySet()) {
                    StructMethod method = owner.getMethod(methodEntry.getKey());
                    if (method != null) captureMethod(path, owner, method, methodEntry.getValue(), lineOffset);
                }
            }
        }

        private void captureMethod(String path, StructClass owner, StructMethod method,
                                   Map<Integer, Integer> lines, int lineOffset) throws IOException {
            boolean expand = method.getInstructionSequence() == null;
            if (expand) method.expandData(owner);
            try {
                var instructions = method.getInstructionSequence();
                if (instructions == null) return;
                for (Instruction instruction : instructions) {
                    if (mapping.disabled) return;
                    Integer line = lines.get(instruction.startOffset);
                    if (line == null) continue;
                    String kind = dereferenceKind(instruction.opcode);
                    if (kind == null) continue;
                    String member = "";
                    if ("instance-method".equals(kind) || "instance-field".equals(kind)) {
                        var reference = owner.getPool().getLinkConstant(instruction.operand(0));
                        if (reference == null || reference.elementname == null) continue;
                        member = reference.elementname;
                    }
                    mapping.add(path, owner.qualifiedName, method.getName(), method.getDescriptor(),
                        Integer.toString(instruction.startOffset), Integer.toString(line + lineOffset), kind, member);
                }
            } finally {
                if (expand) method.releaseResources();
            }
        }
    }

    private static String dereferenceKind(int opcode) {
        return switch (opcode) {
            case opc_invokevirtual, opc_invokeinterface, opc_invokespecial -> "instance-method";
            case opc_getfield, opc_putfield -> "instance-field";
            case opc_iaload, opc_laload, opc_faload, opc_daload, opc_aaload, opc_baload, opc_caload, opc_saload,
                opc_iastore, opc_lastore, opc_fastore, opc_dastore, opc_aastore, opc_bastore, opc_castore, opc_sastore -> "array-access";
            case opc_arraylength -> "array-length";
            case opc_monitorenter, opc_monitorexit -> "monitor";
            default -> null;
        };
    }

    // Vineflower's public saver exports only original source lines, not the method and BCI map.
    // Capture the pinned 1.12.0 mapper while still on the class's decompilation thread.
    private record MapperAccess(Field classes, Field lineOffset) {
        static MapperAccess open() {
            try {
                Field classes = BytecodeSourceMapper.class.getDeclaredField("mapping");
                Field offset = BytecodeSourceMapper.class.getDeclaredField("offset_total");
                return classes.trySetAccessible() && offset.trySetAccessible() ? new MapperAccess(classes, offset) : null;
            } catch (ReflectiveOperationException failure) {
                return null;
            }
        }

        @SuppressWarnings("unchecked")
        Map<String, Map<String, Map<Integer, Integer>>> classes(BytecodeSourceMapper mapper)
            throws IllegalAccessException {
            return (Map<String, Map<String, Map<Integer, Integer>>>) classes.get(mapper);
        }
    }

    private static final class Mapping {
        private final Set<String> rows = new TreeSet<>();
        private int bytes = HEADER.length() + 1;
        private volatile boolean disabled;

        synchronized void add(String... fields) {
            if (disabled) return;
            for (String field : fields) {
                if (field.chars().anyMatch(Character::isISOControl)) {
                    disable();
                    return;
                }
            }
            String row = String.join("\t", fields);
            int size = row.getBytes(StandardCharsets.UTF_8).length + 1;
            if (size > MAX_ROW_BYTES) {
                disable();
            } else if (rows.add(row)) {
                bytes += size;
                if (bytes > MAX_BYTES || rows.size() > MAX_ROWS) disable();
            }
        }

        synchronized void disable() {
            disabled = true;
            rows.clear();
        }

        synchronized void write(Path path) throws IOException {
            try (var writer = Files.newBufferedWriter(path, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
                writer.write(HEADER);
                writer.write('\n');
                for (String row : rows) {
                    writer.write(row);
                    writer.write('\n');
                }
            }
        }
    }

    private static boolean safePath(String path) {
        if (path.startsWith("/") || path.contains("//") || path.contains("\\") || path.contains(":")
            || path.chars().anyMatch(Character::isISOControl)) return false;
        for (String part : path.split("/")) {
            if (part.equals(".") || part.equals("..")) return false;
        }
        return true;
    }

    /** Keep upstream folder formatting and resource handling within the output directory. */
    private static final class SafeDirectorySaver extends DirectoryResultSaver {
        SafeDirectorySaver(File output) {
            super(output);
        }

        @Override
        public void saveFolder(String path) {
            if (safePath(path)) super.saveFolder(path);
        }

        @Override
        public void saveDirEntry(String path, String archive, String entry) {
            if (safePath(entry)) super.saveDirEntry(path, archive, entry);
        }

        @Override
        public void saveClassFile(String path, String name, String entry, String content, int[] lines) {
            if (safePath(path) && safePath(entry)) super.saveClassFile(path, name, entry, content, lines);
        }

        @Override
        public void saveClassEntry(String path, String archive, String name, String entry, String content) {
            if (safePath(entry)) super.saveClassEntry(path, archive, name, entry, content);
        }

        @Override
        public void copyFile(String source, String path, String entry) {
            if (safePath(entry)) super.copyFile(source, path, entry);
        }

        @Override
        public void copyEntry(String source, String path, String archive, String entry) {
            if (safePath(entry)) super.copyEntry(source, path, archive, entry);
        }
    }
}
