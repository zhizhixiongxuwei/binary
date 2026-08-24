package com.binaryscan.checker.c;

import com.binaryscan.checker.c.grammar.PseudoCLexer;
import org.antlr.v4.runtime.CharStreams;
import org.antlr.v4.runtime.CommonTokenStream;
import org.antlr.v4.runtime.Token;
import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Rules migrated from binary_new's ANTLR C checker. The input is usually
 * Ghidra pseudo-C, so evaluation is intentionally tolerant of incomplete
 * declarations while retaining token-based source coordinates.
 */
@Component
final class CAnalyzer {
    static final Set<String> RULE_IDS = Set.of(
        "cwe-242-gets", "cwe-120-bounds", "cwe-134-format", "cwe-78-command",
        "cwe-787-oob-write", "cwe-125-oob-read", "cwe-562-stack-address",
        "cwe-590-invalid-free", "cwe-761-offset-free", "cwe-369-zero-divisor",
        "cwe-377-temp-file", "cwe-252-unchecked-return", "cwe-131-size-calculation",
        "cwe-327-328-weak-crypto", "cwe-732-permissions");

    private static final Set<String> UNSAFE_COPY = Set.of("strcpy", "strcat", "sprintf", "vsprintf");
    private static final Set<String> SCANF = Set.of(
        "scanf", "fscanf", "sscanf", "vscanf", "vfscanf", "vsscanf",
        "wscanf", "fwscanf", "swscanf");
    private static final Set<String> TEMP_APIS = Set.of("tmpnam", "tmpnam_r", "tempnam", "mktemp", "tmpfile");
    private static final Set<String> CHECKED_RETURN_APIS = Set.of(
        "malloc", "calloc", "realloc", "fopen", "open", "openat", "read", "write",
        "recv", "send", "system", "popen", "scanf", "fscanf", "sscanf", "close",
        "remove", "rename", "chdir", "chmod", "fchmod", "setuid", "seteuid",
        "setgid", "setegid", "pthread_create");
    private static final Set<String> ALLOCATORS = Set.of("malloc", "calloc", "realloc", "strdup", "strndup");
    private static final Set<String> TYPE_WORDS = Set.of(
        "void", "char", "short", "int", "long", "float", "double", "signed", "unsigned",
        "bool", "_bool", "size_t", "ssize_t", "undefined", "undefined1", "undefined2",
        "undefined4", "undefined8", "byte", "word", "dword", "qword", "float10");

    List<Models.Finding> analyze(Models.SourceFile file) {
        var lexer = new PseudoCLexer(CharStreams.fromString(file.content()));
        var stream = new CommonTokenStream(lexer);
        stream.fill();
        List<Token> tokens = stream.getTokens().stream()
            .filter(token -> token.getType() != Token.EOF).toList();
        String[] sourceLines = file.content().split("\\n", -1);
        Symbols symbols = collectSymbols(tokens);
        List<CallSite> calls = collectCalls(tokens);
        Emitter emitter = new Emitter(file.path(), sourceLines);

        evaluateCalls(tokens, calls, symbols, emitter);
        evaluateArrayBounds(tokens, symbols, emitter);
        evaluateReturns(tokens, symbols, emitter);
        evaluateZeroDivisors(tokens, emitter);

        emitter.findings.sort(Comparator.comparingInt(Models.Finding::line)
            .thenComparingInt(Models.Finding::column).thenComparing(Models.Finding::ruleId));
        return emitter.findings;
    }

    private static void evaluateCalls(List<Token> tokens, List<CallSite> calls,
                                      Symbols symbols, Emitter emitter) {
        for (CallSite call : calls) {
            String name = normalizeSymbol(call.name().getText());
            if ("gets".equals(name)) {
                emitter.emit(call.name(), "cwe-242-gets", "high", "CWE-242", "Use of gets",
                    "gets cannot bound input and must not be used", Map.of("symbol", call.name().getText()));
            }
            if (UNSAFE_COPY.contains(name)) {
                emitter.emit(call.name(), "cwe-120-bounds", "high", "CWE-120", "Unbounded buffer operation",
                    name + " does not enforce a destination bound", Map.of("symbol", call.name().getText()));
            } else if (SCANF.contains(name)) {
                int formatIndex = scanfFormatIndex(name);
                if (formatIndex < call.arguments().size()
                    && isStringLiteral(call.arguments().get(formatIndex))
                    && hasUnboundedStringConversion(stringLiteralValue(call.arguments().get(formatIndex)))) {
                    emitter.emit(call.name(), "cwe-120-bounds", "high", "CWE-120", "Unbounded scanf conversion",
                        name + " uses an unbounded %s conversion", Map.of("symbol", call.name().getText()));
                }
            }

            int formatIndex = printfFormatIndex(name);
            if (formatIndex >= 0 && formatIndex < call.arguments().size()
                && !isStringLiteral(call.arguments().get(formatIndex))) {
                emitter.emit(call.name(), "cwe-134-format", "high", "CWE-134", "Externally controlled format string",
                    name + " receives a non-literal format string", Map.of("symbol", call.name().getText()));
            }
            if (("system".equals(name) || "popen".equals(name)) && !call.arguments().isEmpty()
                && !isStringLiteral(call.arguments().getFirst())) {
                emitter.emit(call.name(), "cwe-78-command", "high", "CWE-78", "Command injection",
                    name + " receives a non-literal command", Map.of("symbol", call.name().getText()));
            }
            if (TEMP_APIS.contains(name)) {
                emitter.emit(call.name(), "cwe-377-temp-file", "medium", "CWE-377", "Insecure temporary file",
                    name + " uses an insecure temporary-file API", Map.of("symbol", call.name().getText()));
            }
            String weakCwe = weakCryptoCwe(name);
            if (weakCwe != null) {
                emitter.emit(call.name(), "cwe-327-328-weak-crypto", "medium", weakCwe, "Weak cryptography",
                    name + " selects a weak cryptographic primitive", Map.of("symbol", call.name().getText()));
            }
            if (CHECKED_RETURN_APIS.contains(name) && isDiscardedCall(tokens, call)) {
                emitter.emit(call.name(), "cwe-252-unchecked-return", "medium", "CWE-252", "Unchecked return value",
                    "return value from " + name + " is ignored", Map.of("symbol", call.name().getText()));
            }
            evaluateFree(tokens, call, name, symbols, emitter);
            evaluateAllocationSize(tokens, call, name, symbols, emitter);
            evaluatePermissions(call, name, emitter);
        }
    }

    private static void evaluateFree(List<Token> tokens, CallSite call, String name,
                                     Symbols symbols, Emitter emitter) {
        if (!"free".equals(name) || call.arguments().isEmpty()) return;
        List<Token> argument = stripOuterParentheses(call.arguments().getFirst());
        if (argument.isEmpty()) return;
        String first = isIdentifier(argument.getFirst()) ? argument.getFirst().getText() : null;
        PointerState state = pointerStateAt(tokens, call.nameIndex(), first);
        boolean explicitOffset = contains(argument, "+") || contains(argument, "-")
            || (argument.size() >= 3 && text(argument.get(0), "&")
                && isIdentifier(argument.get(1)) && text(argument.get(2), "["))
            || state.offset();
        if (explicitOffset) {
            emitter.emit(call.name(), "cwe-761-offset-free", "high", "CWE-761", "Free of offset pointer",
                "free is called with an offset pointer", Map.of("symbol", call.name().getText()));
            return;
        }
        boolean address = text(argument.getFirst(), "&");
        boolean literal = isStringLiteral(argument) || integer(argument).isPresent();
        boolean stackArray = first != null && symbols.arrays().containsKey(first);
        boolean knownNonHeap = state.nonHeap();
        boolean scalar = first != null && symbols.locals().contains(first)
            && !symbols.pointers().contains(first) && !symbols.arrays().containsKey(first);
        if (address || literal || stackArray || knownNonHeap || scalar) {
            emitter.emit(call.name(), "cwe-590-invalid-free", "high", "CWE-590", "Free of non-heap memory",
                "free is called with storage that was not heap allocated", Map.of("symbol", call.name().getText()));
        }
    }

    private static void evaluateAllocationSize(List<Token> tokens, CallSite call, String name,
                                               Symbols symbols, Emitter emitter) {
        if (!("malloc".equals(name) || "calloc".equals(name) || "realloc".equals(name))) return;
        int sizeIndex = "malloc".equals(name) ? 0 : 1;
        if (call.arguments().size() <= sizeIndex) return;
        String target = assignedTarget(tokens, call.nameIndex());
        if (target != null && symbols.pointers().contains(target)
            && containsSizeofVariable(call.arguments().get(sizeIndex), target)) {
            emitter.emit(call.name(), "cwe-131-size-calculation", "high", "CWE-131", "Incorrect allocation size",
                "allocation uses sizeof(" + target + "), which is the pointer size", Map.of("symbol", target));
        }
    }

    private static void evaluatePermissions(CallSite call, String name, Emitter emitter) {
        int modeIndex = switch (name) {
            case "chmod", "fchmod", "creat", "mkdir" -> 1;
            case "open" -> 2;
            case "openat" -> 3;
            default -> -1;
        };
        if (modeIndex < 0 || modeIndex >= call.arguments().size()) return;
        Optional<BigInteger> mode = integer(call.arguments().get(modeIndex));
        if (mode.isPresent() && mode.get().signum() >= 0
            && mode.get().and(BigInteger.valueOf(0002)).signum() != 0) {
            emitter.emit(call.name(), "cwe-732-permissions", "medium", "CWE-732", "Overly permissive file mode",
                name + " grants write permission to other users", Map.of("mode", mode.get().toString(8)));
        }
    }

    private static void evaluateArrayBounds(List<Token> tokens, Symbols symbols, Emitter emitter) {
        for (int index = 0; index + 3 < tokens.size(); index++) {
            Token name = tokens.get(index);
            if (!isIdentifier(name) || !text(tokens.get(index + 1), "[")
                || symbols.declarationIndexes().contains(index)) continue;
            List<Long> dimensions = symbols.arrays().get(name.getText());
            if (dimensions == null) continue;
            int cursor = index + 1;
            for (int dimension = 0; dimension < dimensions.size() && cursor < tokens.size()
                && text(tokens.get(cursor), "["); dimension++) {
                int close = matching(tokens, cursor, "[", "]");
                if (close < 0) break;
                Optional<BigInteger> value = integer(tokens.subList(cursor + 1, close));
                if (value.isPresent() && (value.get().signum() < 0
                    || value.get().compareTo(BigInteger.valueOf(dimensions.get(dimension))) >= 0)) {
                    boolean write = isWriteAccess(tokens, close);
                    emitter.emit(name, write ? "cwe-787-oob-write" : "cwe-125-oob-read", "high",
                        write ? "CWE-787" : "CWE-125", write ? "Out-of-bounds write" : "Out-of-bounds read",
                        "array index " + value.get() + " is outside " + name.getText() + "["
                            + dimensions.get(dimension) + "]", Map.of("array", name.getText(), "index", value.get()));
                }
                cursor = close + 1;
            }
        }
    }

    private static void evaluateReturns(List<Token> tokens, Symbols symbols, Emitter emitter) {
        for (int index = 0; index + 1 < tokens.size(); index++) {
            if (!text(tokens.get(index), "return")) continue;
            int cursor = index + 1;
            while (cursor < tokens.size() && text(tokens.get(cursor), "(")) cursor++;
            String returned = null;
            if (cursor + 1 < tokens.size() && text(tokens.get(cursor), "&") && isIdentifier(tokens.get(cursor + 1))) {
                returned = tokens.get(cursor + 1).getText();
            } else if (cursor < tokens.size() && isIdentifier(tokens.get(cursor))
                && symbols.arrays().containsKey(tokens.get(cursor).getText())
                && (cursor + 1 >= tokens.size() || !text(tokens.get(cursor + 1), "["))) {
                returned = tokens.get(cursor).getText();
            }
            if (returned != null && symbols.locals().contains(returned)) {
                emitter.emit(tokens.get(index), "cwe-562-stack-address", "high", "CWE-562", "Return of stack address",
                    "function returns the address of local storage " + returned, Map.of("symbol", returned));
            }
        }
    }

    private static void evaluateZeroDivisors(List<Token> tokens, Emitter emitter) {
        for (int index = 0; index + 1 < tokens.size(); index++) {
            if (!(text(tokens.get(index), "/") || text(tokens.get(index), "%"))) continue;
            int cursor = index + 1;
            while (cursor < tokens.size() && (text(tokens.get(cursor), "(") || text(tokens.get(cursor), "+"))) cursor++;
            if (cursor < tokens.size() && integer(List.of(tokens.get(cursor))).filter(BigInteger.ZERO::equals).isPresent()) {
                emitter.emit(tokens.get(index), "cwe-369-zero-divisor", "high", "CWE-369", "Division by zero",
                    "division or remainder uses a constant zero divisor", Map.of("operator", tokens.get(index).getText()));
            }
        }
    }

    private static Symbols collectSymbols(List<Token> tokens) {
        Map<String, List<Long>> arrays = new LinkedHashMap<>();
        Set<String> locals = new HashSet<>();
        Set<String> pointers = new HashSet<>();
        Set<Integer> declarationIndexes = new HashSet<>();
        int braceDepth = 0;
        for (int index = 0; index < tokens.size(); index++) {
            if (text(tokens.get(index), "{")) { braceDepth++; continue; }
            if (text(tokens.get(index), "}")) { braceDepth = Math.max(0, braceDepth - 1); continue; }
            if (braceDepth <= 0 || !isTypeWord(tokens.get(index))) continue;
            int end = index;
            while (end < tokens.size() && !text(tokens.get(end), ";") && !text(tokens.get(end), "{")) end++;
            if (end >= tokens.size() || text(tokens.get(end), "{")) continue;
            for (int cursor = index + 1; cursor < end; cursor++) {
                if (!isIdentifier(tokens.get(cursor)) || isTypeWord(tokens.get(cursor))) continue;
                boolean call = cursor + 1 < end && text(tokens.get(cursor + 1), "(");
                boolean member = cursor > index && (text(tokens.get(cursor - 1), ".") || text(tokens.get(cursor - 1), ">"));
                if (call || member) continue;
                Token previous = cursor > index ? tokens.get(cursor - 1) : null;
                Token next = cursor + 1 < tokens.size() ? tokens.get(cursor + 1) : null;
                boolean declarator = text(previous, "*") || text(previous, ",") || isTypeWord(previous)
                    || text(next, "[") || text(next, "=") || text(next, ",") || text(next, ";");
                if (!declarator) continue;
                String name = tokens.get(cursor).getText();
                locals.add(name);
                if (text(previous, "*")) pointers.add(name);
                if (text(next, "[")) {
                    List<Long> dimensions = new ArrayList<>();
                    int dimensionCursor = cursor + 1;
                    while (dimensionCursor < end && text(tokens.get(dimensionCursor), "[")) {
                        int close = matching(tokens, dimensionCursor, "[", "]");
                        if (close < 0 || close > end) break;
                        Optional<BigInteger> value = integer(tokens.subList(dimensionCursor + 1, close));
                        dimensions.add(value.filter(number -> number.signum() > 0 && number.bitLength() < 63)
                            .map(BigInteger::longValue).orElse(-1L));
                        dimensionCursor = close + 1;
                    }
                    arrays.putIfAbsent(name, List.copyOf(dimensions));
                    declarationIndexes.add(cursor);
                }
            }
            index = end;
        }
        return new Symbols(arrays, locals, pointers, declarationIndexes);
    }

    private static List<CallSite> collectCalls(List<Token> tokens) {
        List<CallSite> calls = new ArrayList<>();
        for (int index = 0; index + 1 < tokens.size(); index++) {
            if (!isIdentifier(tokens.get(index)) || !text(tokens.get(index + 1), "(")) continue;
            int close = matching(tokens, index + 1, "(", ")");
            if (close < 0) continue;
            // Ghidra emits external thunks as ordinary-looking definitions,
            // for example `_system(char *param_1) { ... }`. Treating the
            // definition header as a call would report an injection merely
            // because a binary imports the symbol.
            if (close + 1 < tokens.size() && text(tokens.get(close + 1), "{")) continue;
            List<List<Token>> arguments = splitArguments(tokens, index + 2, close);
            calls.add(new CallSite(tokens.get(index), index, close, arguments));
        }
        return calls;
    }

    private static List<List<Token>> splitArguments(List<Token> tokens, int start, int end) {
        if (start >= end) return List.of();
        List<List<Token>> result = new ArrayList<>();
        int part = start;
        int parens = 0;
        int brackets = 0;
        int braces = 0;
        for (int index = start; index < end; index++) {
            String value = tokens.get(index).getText();
            if ("(".equals(value)) parens++;
            else if (")".equals(value)) parens--;
            else if ("[".equals(value)) brackets++;
            else if ("]".equals(value)) brackets--;
            else if ("{".equals(value)) braces++;
            else if ("}".equals(value)) braces--;
            else if (",".equals(value) && parens == 0 && brackets == 0 && braces == 0) {
                result.add(List.copyOf(tokens.subList(part, index)));
                part = index + 1;
            }
        }
        result.add(List.copyOf(tokens.subList(part, end)));
        return result;
    }

    private static PointerState pointerStateAt(List<Token> tokens, int limit, String variable) {
        if (variable == null) return new PointerState(false, false);
        boolean offset = false;
        boolean nonHeap = false;
        for (int index = 0; index < limit; index++) {
            if (!text(tokens.get(index), variable)) continue;
            if (index + 2 < limit
                && ((text(tokens.get(index + 1), "+") && text(tokens.get(index + 2), "+"))
                    || (text(tokens.get(index + 1), "-") && text(tokens.get(index + 2), "-")))) {
                offset = true;
            } else if (index >= 2
                && ((text(tokens.get(index - 2), "+") && text(tokens.get(index - 1), "+"))
                    || (text(tokens.get(index - 2), "-") && text(tokens.get(index - 1), "-")))) {
                offset = true;
            } else if (index + 2 < limit && text(tokens.get(index + 1), "+") && text(tokens.get(index + 2), "=")) {
                offset = true;
            } else if (index + 2 < limit && text(tokens.get(index + 1), "-") && text(tokens.get(index + 2), "=")) {
                offset = true;
            } else if (index + 1 < limit && text(tokens.get(index + 1), "=")) {
                int end = index + 2;
                while (end < limit && !text(tokens.get(end), ";")) end++;
                List<Token> rhs = tokens.subList(index + 2, end);
                boolean allocator = rhs.stream().anyMatch(token -> ALLOCATORS.contains(normalizeSymbol(token.getText())));
                if (allocator) {
                    offset = false;
                    nonHeap = false;
                } else if (!rhs.isEmpty() && text(rhs.getFirst(), "&")) {
                    offset = false;
                    nonHeap = true;
                } else if (rhs.stream().anyMatch(token -> text(token, "+") || text(token, "-"))) {
                    offset = true;
                }
            }
        }
        return new PointerState(offset, nonHeap);
    }

    private static boolean isDiscardedCall(List<Token> tokens, CallSite call) {
        if (call.closeIndex() + 1 >= tokens.size() || !text(tokens.get(call.closeIndex() + 1), ";")) return false;
        int start = call.nameIndex() - 1;
        while (start >= 0 && !text(tokens.get(start), ";") && !text(tokens.get(start), "{")
            && !text(tokens.get(start), "}")) start--;
        return start + 1 == call.nameIndex();
    }

    private static String assignedTarget(List<Token> tokens, int callIndex) {
        int start = callIndex - 1;
        while (start >= 0 && !text(tokens.get(start), ";") && !text(tokens.get(start), "{")
            && !text(tokens.get(start), "}")) start--;
        for (int index = callIndex - 1; index > start; index--) {
            if (!text(tokens.get(index), "=")) continue;
            for (int candidate = index - 1; candidate > start; candidate--) {
                if (isIdentifier(tokens.get(candidate))) return tokens.get(candidate).getText();
            }
        }
        return null;
    }

    private static boolean containsSizeofVariable(List<Token> tokens, String variable) {
        for (int index = 0; index < tokens.size(); index++) {
            if (!text(tokens.get(index), "sizeof")) continue;
            int candidate = index + 1;
            if (candidate < tokens.size() && text(tokens.get(candidate), "(")) candidate++;
            if (candidate < tokens.size() && text(tokens.get(candidate), variable)) return true;
        }
        return false;
    }

    private static boolean isWriteAccess(List<Token> tokens, int close) {
        int cursor = close + 1;
        if (cursor >= tokens.size()) return false;
        // An access used as another array's index is a read even when the
        // outer access is the assignment target: target[source[4]] = 0.
        if (text(tokens.get(cursor), "]")) return false;
        if (text(tokens.get(cursor), "=")) return true;
        if (cursor + 1 < tokens.size() && Set.of("+", "-", "*", "/", "%", "<", ">", "&", "^", "|")
            .contains(tokens.get(cursor).getText()) && text(tokens.get(cursor + 1), "=")) return true;
        return false;
    }

    private static int matching(List<Token> tokens, int open, String left, String right) {
        int depth = 0;
        for (int index = open; index < tokens.size(); index++) {
            if (text(tokens.get(index), left)) depth++;
            else if (text(tokens.get(index), right) && --depth == 0) return index;
        }
        return -1;
    }

    private static List<Token> stripOuterParentheses(List<Token> input) {
        List<Token> tokens = input;
        while (tokens.size() >= 2 && text(tokens.getFirst(), "(") && text(tokens.getLast(), ")")
            && matching(tokens, 0, "(", ")") == tokens.size() - 1) {
            tokens = tokens.subList(1, tokens.size() - 1);
        }
        return tokens;
    }

    private static Optional<BigInteger> integer(List<Token> input) {
        List<Token> tokens = stripOuterParentheses(input);
        if (tokens.isEmpty()) return Optional.empty();
        boolean negative = false;
        int index = 0;
        if (text(tokens.getFirst(), "+") || text(tokens.getFirst(), "-")) {
            negative = text(tokens.getFirst(), "-");
            index++;
        }
        if (index != tokens.size() - 1 || tokens.get(index).getType() != PseudoCLexer.Number) return Optional.empty();
        String value = tokens.get(index).getText().replaceAll("(?i)[uUlL]+$", "");
        try {
            int radix = 10;
            if (value.startsWith("0x") || value.startsWith("0X")) { radix = 16; value = value.substring(2); }
            else if (value.startsWith("0") && value.length() > 1) { radix = 8; value = value.substring(1); }
            BigInteger number = new BigInteger(value.isEmpty() ? "0" : value, radix);
            return Optional.of(negative ? number.negate() : number);
        } catch (NumberFormatException ignored) {
            return Optional.empty();
        }
    }

    private static boolean isStringLiteral(List<Token> tokens) {
        List<Token> stripped = stripOuterParentheses(tokens);
        return !stripped.isEmpty() && stripped.stream().allMatch(token -> token.getType() == PseudoCLexer.StringLiteral);
    }

    private static String stringLiteralValue(List<Token> tokens) {
        StringBuilder value = new StringBuilder();
        for (Token token : stripOuterParentheses(tokens)) {
            if (token.getType() != PseudoCLexer.StringLiteral) continue;
            String text = token.getText();
            if (text.length() >= 2) value.append(text, 1, text.length() - 1);
        }
        return value.toString();
    }

    private static boolean hasUnboundedStringConversion(String format) {
        for (int index = 0; index < format.length(); index++) {
            if (format.charAt(index) != '%') continue;
            if (index + 1 < format.length() && format.charAt(index + 1) == '%') { index++; continue; }
            int cursor = index + 1;
            if (cursor < format.length() && format.charAt(cursor) == '*') cursor++;
            boolean width = false;
            while (cursor < format.length() && Character.isDigit(format.charAt(cursor))) { width = true; cursor++; }
            while (cursor < format.length() && "hljztL".indexOf(format.charAt(cursor)) >= 0) cursor++;
            if (cursor < format.length() && format.charAt(cursor) == 's' && !width) return true;
        }
        return false;
    }

    private static int scanfFormatIndex(String name) {
        return switch (name) {
            case "fscanf", "sscanf", "vfscanf", "vsscanf", "fwscanf", "swscanf" -> 1;
            default -> 0;
        };
    }

    private static int printfFormatIndex(String name) {
        return switch (name) {
            case "printf", "vprintf", "wprintf", "vwprintf" -> 0;
            case "fprintf", "vfprintf", "dprintf", "vdprintf", "sprintf", "vsprintf", "fwprintf", "vfwprintf" -> 1;
            case "snprintf", "vsnprintf", "swprintf", "vswprintf" -> 2;
            case "syslog", "vsyslog" -> 1;
            default -> -1;
        };
    }

    private static String weakCryptoCwe(String name) {
        String lower = name.toLowerCase(Locale.ROOT);
        if (lower.contains("md5") || lower.contains("sha1") || lower.equals("sha") || lower.startsWith("sha_")) {
            return "CWE-328";
        }
        if (lower.startsWith("des_") || lower.startsWith("rc4") || lower.contains("evp_des")
            || lower.contains("evp_rc4") || lower.equals("crypt") || lower.equals("ecb_encrypt")) {
            return "CWE-327";
        }
        return null;
    }

    private static String normalizeSymbol(String raw) {
        String name = raw.toLowerCase(Locale.ROOT).replaceFirst("^_+", "");
        if (name.startsWith("isoc99_")) name = name.substring("isoc99_".length());
        if (name.endsWith("_chk")) name = name.substring(0, name.length() - 4);
        return name;
    }
    private static boolean isTypeWord(Token token) {
        return token != null && TYPE_WORDS.contains(token.getText().toLowerCase(Locale.ROOT));
    }
    private static boolean isIdentifier(Token token) { return token != null && token.getType() == PseudoCLexer.Identifier; }
    private static boolean text(Token token, String expected) { return token != null && expected.equals(token.getText()); }
    private static boolean contains(List<Token> tokens, String expected) {
        return tokens.stream().anyMatch(token -> text(token, expected));
    }

    private record Symbols(Map<String, List<Long>> arrays, Set<String> locals,
                           Set<String> pointers, Set<Integer> declarationIndexes) {}
    private record CallSite(Token name, int nameIndex, int closeIndex, List<List<Token>> arguments) {}
    private record PointerState(boolean offset, boolean nonHeap) {}

    private static final class Emitter {
        private final String path;
        private final String[] sourceLines;
        private final Set<String> dedupe = new HashSet<>();
        private final List<Models.Finding> findings = new ArrayList<>();

        private Emitter(String path, String[] sourceLines) {
            this.path = path;
            this.sourceLines = sourceLines;
        }

        private void emit(Token token, String ruleId, String severity, String cwe, String title,
                          String message, Map<String, Object> evidence) {
            int line = Math.max(1, token.getLine());
            int column = utf16Column(sourceLines, line, token.getCharPositionInLine());
            if (!dedupe.add(ruleId + ':' + line + ':' + column)) return;
            findings.add(new Models.Finding(ruleId, severity, cwe, path, line, column,
                title, message, new HashMap<>(evidence)));
        }
    }

    /** Convert ANTLR's code-point offset to Monaco's one-based UTF-16 column. */
    private static int utf16Column(String[] sourceLines, int line, int codePointOffset) {
        if (line < 1 || line > sourceLines.length || codePointOffset < 0) return 1;
        String sourceLine = sourceLines[line - 1];
        int codePointCount = sourceLine.codePointCount(0, sourceLine.length());
        if (codePointOffset > codePointCount) return 1;
        return sourceLine.offsetByCodePoints(0, codePointOffset) + 1;
    }
}
