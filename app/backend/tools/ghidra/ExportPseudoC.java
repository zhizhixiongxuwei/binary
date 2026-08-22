// Ghidra headless post-script arguments: <output-dir> <max-functions> <max-bytes>

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

public final class ExportPseudoC extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3) {
            throw new IllegalArgumentException("expected output-dir, max-functions and max-bytes");
        }
        Path output = Path.of(args[0]).toAbsolutePath().normalize();
        int maxFunctions = Integer.parseInt(args[1]);
        long maxBytes = Long.parseLong(args[2]);
        if (maxFunctions <= 0 || maxBytes <= 0) {
            throw new IllegalArgumentException("output limits must be positive");
        }
        Files.createDirectories(output);

        List<Function> functions = new ArrayList<>();
        boolean partial = false;
        for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
            if (function.isExternal()) {
                continue;
            }
            if (functions.size() >= maxFunctions) {
                partial = true;
                break;
            }
            functions.add(function);
        }
        functions.sort(Comparator.comparing(item -> item.getEntryPoint().toString()));

        long written = 0;
        int ordinal = 0;
        DecompInterface decompiler = new DecompInterface();
        if (!decompiler.openProgram(currentProgram)) {
            throw new IllegalStateException("Ghidra decompiler cannot open the imported program");
        }
        try {
            for (Function function : functions) {
                checkCancelled();
                DecompileResults result = decompiler.decompileFunction(function, 60, monitor);
                if (!result.decompileCompleted() || result.getDecompiledFunction() == null) {
                    partial = true;
                    continue;
                }
                byte[] source = result.getDecompiledFunction().getC().getBytes(StandardCharsets.UTF_8);
                if (source.length > maxBytes - written) {
                    partial = true;
                    break;
                }
                String address = function.getEntryPoint().toString().replaceAll("[^A-Za-z0-9_-]", "_");
                Path destination = output.resolve(String.format("%05d_%s.c", ordinal, address));
                Files.write(destination, source);
                written += source.length;
                ordinal++;
            }
        } finally {
            decompiler.dispose();
        }
        if (partial) {
            Files.writeString(output.resolve(".binaryscan-partial"), "partial\n", StandardCharsets.UTF_8);
        }
        if (ordinal == 0) {
            throw new IllegalStateException("Ghidra produced no decompiled functions");
        }
    }
}
