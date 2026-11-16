package com.binaryscan.checker.java;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.*;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.type.Type;

import java.util.*;
import static com.binaryscan.checker.java.NullDereferenceAnalyzer.*;

/** Bounded project index. Stores signatures and nullness summaries, never CompilationUnits. */
final class ProjectContext {
    static final int METHOD_LIMIT = 20_000;
    static final int EDGE_LIMIT = 100_000;
    static final int TRACE_LIMIT = 12;
    record FieldInfo(String type, Nullness state, boolean isStatic) {}
    static final class TypeInfo {
        String name, path, packageName;
        boolean mapper, isInterface, isFinal;
        List<String> imports, wildcards, parents;
        Map<String, FieldInfo> fields = new LinkedHashMap<>();
        List<MethodInfo> methods = new ArrayList<>();
    }
    static final class MethodInfo {
        String key, name, result;
        TypeInfo owner;
        List<String> parameters;
        boolean isStatic, body, varargs, exact;
        Nullness annotation = Nullness.UNKNOWN;
        Value[] inputs;
        Summary summary;
    }
    record Summary(Nullness state, int parameter, List<Map<String,Object>> trace) {}
    final Map<String, TypeInfo> types = new LinkedHashMap<>();
    final Set<String> ambiguousTypes = new HashSet<>();
    final Map<String, MethodInfo> methods = new LinkedHashMap<>();
    final LinkedHashMap<String, Models.Diagnostic> diagnostics = new LinkedHashMap<>();
    final Set<String> unresolved = new HashSet<>();
    final Set<String> edges = new HashSet<>();
    final Set<String> analyzed = new HashSet<>();
    final long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.MINUTES.toNanos(3);
    boolean changed;
    boolean recording;

    void checkBudget() {
        if (Thread.currentThread().isInterrupted()) throw new BudgetExceeded("JAVA_ANALYSIS_CANCELLED", "analysis cancelled");
        if (System.nanoTime() > deadline) throw new BudgetExceeded("JAVA_TIME_LIMIT", "project analysis exceeded three minutes");
    }
    void register(String path, CompilationUnit unit) {
        for (TypeDeclaration<?> declaration : unit.findAll(TypeDeclaration.class)) {
            TypeInfo type = new TypeInfo();
            type.packageName = unit.getPackageDeclaration().map(p -> p.getNameAsString()).orElse("");
            type.name = qualifiedName(declaration, type.packageName); type.path = path;
            type.imports = unit.getImports().stream().filter(i -> !i.isAsterisk() && !i.isStatic()).map(i -> i.getNameAsString()).toList();
            type.wildcards = unit.getImports().stream().filter(i -> i.isAsterisk() && !i.isStatic()).map(i -> i.getNameAsString()).toList();
            type.parents = new ArrayList<>();
            if (declaration instanceof ClassOrInterfaceDeclaration c) {
                type.isInterface = c.isInterface();
                type.isFinal = c.isFinal();
                c.getExtendedTypes().forEach(p -> type.parents.add(p.asString()));
                c.getImplementedTypes().forEach(p -> type.parents.add(p.asString()));
            }
            type.mapper = declaration.getAnnotations().stream().anyMatch(a ->
                qualify(a.getNameAsString(), type).equals("org.apache.ibatis.annotations.Mapper"));
            for (FieldDeclaration field : declaration.getFields()) for (var variable : field.getVariables()) {
                Nullness state = nullable(field, type) ? Nullness.MAYBE_NULL : Nullness.UNKNOWN;
                if (variable.getInitializer().filter(e -> e.isNullLiteralExpr()).isPresent()) state = Nullness.NULL;
                type.fields.put(variable.getNameAsString(), new FieldInfo(variable.getTypeAsString(), state, field.isStatic() || type.isInterface));
            }
            if (ambiguousTypes.contains(type.name) || types.putIfAbsent(type.name, type) != null) {
                ambiguousTypes.add(type.name); types.remove(type.name);
                diagnostic("JAVA_DUPLICATE_TYPE", path, declaration, "duplicate project type: " + type.name); continue;
            }
            for (var method : declaration.getMethods()) {
                if (methods.size() >= METHOD_LIMIT) throw new BudgetExceeded("JAVA_METHOD_LIMIT", "project exceeds 20000 methods");
                MethodInfo info = new MethodInfo(); info.owner = type; info.name = method.getNameAsString();
                info.result = method.getTypeAsString(); info.isStatic = method.isStatic(); info.body = method.getBody().isPresent();
                info.exact = method.isStatic() || method.isPrivate() || method.isFinal() || type.isFinal;
                info.parameters = method.getParameters().stream().map(p -> p.getTypeAsString() + (p.isVarArgs() ? "[]" : "")).toList();
                info.varargs = !method.getParameters().isEmpty() && method.getParameter(method.getParameters().size() - 1).isVarArgs();
                info.key = type.name + "#" + info.name + "(" + String.join(",", info.parameters) + ")";
                info.inputs = new Value[info.parameters.size()];
                Arrays.fill(info.inputs, UNKNOWN);
                if (nullable(method, type)) info.annotation = Nullness.MAYBE_NULL;
                type.methods.add(info); methods.put(info.key, info);
            }
        }
    }
    private boolean nullable(BodyDeclaration<?> declaration, TypeInfo scope) {
        return nullableAnnotations(declaration.getAnnotations(), scope);
    }
    boolean nullableAnnotations(List<com.github.javaparser.ast.expr.AnnotationExpr> annotations, TypeInfo scope) {
        return annotations.stream().anyMatch(a -> Set.of("javax.annotation.Nullable", "jakarta.annotation.Nullable",
            "javax.annotation.CheckForNull", "org.jetbrains.annotations.Nullable", "org.springframework.lang.Nullable",
            "org.jspecify.annotations.Nullable", "edu.umd.cs.findbugs.annotations.CheckForNull").contains(qualify(a.getNameAsString(), scope)));
    }
    static String qualifiedName(TypeDeclaration<?> declaration, String pkg) {
        Deque<String> names = new ArrayDeque<>(); names.addFirst(declaration.getNameAsString());
        Node parent = declaration.getParentNode().orElse(null);
        while (parent != null) {
            if (parent instanceof TypeDeclaration<?> type) names.addFirst(type.getNameAsString());
            parent = parent.getParentNode().orElse(null);
        }
        return (pkg.isEmpty() ? "" : pkg + ".") + String.join(".", names);
    }
    TypeInfo owner(Node node, CompilationUnit unit) {
        Node parent = node.getParentNode().orElse(null);
        while (parent != null && !(parent instanceof TypeDeclaration<?>)) {
            if (parent instanceof com.github.javaparser.ast.expr.ObjectCreationExpr creation && creation.getAnonymousClassBody().isPresent()) return null;
            parent = parent.getParentNode().orElse(null);
        }
        var declaration = node.findAncestor(TypeDeclaration.class).orElse(null);
        return declaration == null ? null : types.get(qualifiedName(declaration, unit.getPackageDeclaration().map(p -> p.getNameAsString()).orElse("")));
    }
    MethodInfo method(CallableDeclaration<?> declaration, CompilationUnit unit) {
        TypeInfo type = owner(declaration, unit);
        if (type == null) return null;
        return methods.get(type.name + "#" + declaration.getNameAsString() + "(" + declaration.getParameters().stream()
            .map(p -> p.getTypeAsString() + (p.isVarArgs() ? "[]" : "")).collect(java.util.stream.Collectors.joining(",")) + ")");
    }
    String qualify(String name, TypeInfo owner) {
        String raw = erase(name);
        if (raw.isEmpty() || owner == null) return raw;
        if (raw.contains(".") && Character.isLowerCase(raw.charAt(0))) return raw;
        for (String imported : owner.imports) if (imported.endsWith("." + raw)) return imported;
        String same = owner.packageName.isEmpty() ? raw : owner.packageName + "." + raw;
        if (types.containsKey(same) || ambiguousTypes.contains(same)) return same;
        for (String wildcard : owner.wildcards) if (types.containsKey(wildcard + "." + raw)
            || Set.of("java.util", "java.lang", "org.apache.ibatis.annotations").contains(wildcard)) return wildcard + "." + raw;
        if (Set.of("Object", "String", "Integer", "Long", "Boolean", "Double", "Float", "Short", "Byte", "Character", "StringBuilder", "CharSequence").contains(raw)) return "java.lang." + raw;
        return raw;
    }
    static String erase(String name) {
        if (name == null) return "";
        return name.replaceAll("<.*>", "").replace("[]", "").replace("? extends ", "").trim();
    }
    String qualifyType(String name, TypeInfo owner) {
        Type type = SourceParsing.type(name);
        if (type == null) return name;
        if (type.isArrayType()) return qualifyType(type.asArrayType().getComponentType().asString(), owner) + "[]";
        if (!type.isClassOrInterfaceType()) return type.asString();
        var reference = type.asClassOrInterfaceType();
        String qualified = qualify(reference.getNameWithScope(), owner);
        return qualified + reference.getTypeArguments().map(arguments -> "<" + arguments.stream()
            .map(argument -> qualifyType(argument.asString(), owner)).collect(java.util.stream.Collectors.joining(",")) + ">").orElse("");
    }
    boolean inherits(String name, String target, TypeInfo scope) { return inherits(name, target, scope, new HashSet<>()); }
    boolean mapType(String name, TypeInfo scope) {
        return Set.of("java.util.Map", "java.util.SortedMap", "java.util.NavigableMap", "java.util.HashMap", "java.util.LinkedHashMap",
            "java.util.TreeMap", "java.util.WeakHashMap", "java.util.IdentityHashMap", "java.util.Hashtable",
            "java.util.concurrent.ConcurrentMap", "java.util.concurrent.ConcurrentHashMap", "java.util.concurrent.ConcurrentSkipListMap")
            .contains(qualify(name, scope)) || inherits(name, "java.util.Map", scope);
    }
    private boolean inherits(String name, String target, TypeInfo scope, Set<String> seen) {
        String qualified = qualify(name, scope);
        if (qualified.equals(target)) return true;
        if (seen.size() > 32 || !seen.add(qualified)) return false;
        TypeInfo type = types.get(qualified);
        return type != null && type.parents.stream().anyMatch(p -> inherits(p, target, type, seen));
    }
    boolean mapper(TypeInfo type) {
        return type != null && (type.mapper || inherits(type.name, "com.baomidou.mybatisplus.core.mapper.BaseMapper", type)
            || type.parents.stream().anyMatch(p -> { var parent = types.get(qualify(p, type)); return parent != null && parent.mapper; }));
    }
    FieldInfo field(TypeInfo type, String name) {
        return field(type, name, new HashSet<>());
    }
    private FieldInfo field(TypeInfo type, String name, Set<String> seen) {
        if (type == null || !seen.add(type.name) || seen.size() > 32) return null;
        if (type.fields.containsKey(name)) return type.fields.get(name);
        for (String parent : type.parents) { var value = field(types.get(qualify(parent, type)), name, seen); if (value != null) return value; }
        return null;
    }
    List<MethodInfo> targets(TypeInfo owner, String receiver, MethodCallExpr call, List<Value> arguments) {
        TypeInfo type = receiver.isEmpty() ? owner : types.get(qualify(receiver, owner));
        if (type == null) return List.of();
        List<MethodInfo> matches = new ArrayList<>(); collect(type, call.getNameAsString(), arguments.size(), matches, new HashSet<>());
        // Refuse to guess among overloads whose argument types are unavailable.
        if (matches.size() > 1) {
            var exact = matches.stream().filter(m -> {
                for (int i = 0; i < Math.min(m.parameters.size(), arguments.size()); i++) {
                    if (arguments.get(i).type() == null || !qualify(arguments.get(i).type().asString(), owner).equals(qualify(m.parameters.get(i), m.owner))) return false;
                }
                return true;
            }).toList();
            if (!exact.isEmpty()) matches = new ArrayList<>(exact);
        }
        if ((type.isInterface || matches.stream().anyMatch(m -> !m.exact)) && matches.stream().noneMatch(m -> m.exact)) {
            for (TypeInfo candidate : types.values()) if (!candidate.isInterface && inherits(candidate.name, type.name, candidate))
                collect(candidate, call.getNameAsString(), arguments.size(), matches, new HashSet<>());
            if (matches.stream().anyMatch(m -> m.body)) matches.removeIf(m -> !m.body);
        }
        matches = new ArrayList<>(matches.stream().distinct().toList());
        if (matches.size() > 8) { unresolved(call, owner, "virtual call has more than eight candidate targets"); return List.of(); }
        return matches;
    }
    private void collect(TypeInfo type, String name, int arguments, List<MethodInfo> result, Set<String> seen) {
        if (type == null || !seen.add(type.name) || seen.size() > 32) return;
        var local = type.methods.stream().filter(m -> m.name.equals(name) && (m.parameters.size() == arguments || m.varargs && arguments >= m.parameters.size() - 1)).toList();
        result.addAll(local);
        if (local.isEmpty()) for (String parent : type.parents) collect(types.get(qualify(parent, type)), name, arguments, result, seen);
    }
    Value invocation(MethodInfo caller, TypeInfo scope, Value receiver, MethodCallExpr call, List<Value> arguments) {
        checkBudget();
        String receiverName = receiver.type() == null ? call.getScope().filter(s -> !s.isThisExpr() && !s.isSuperExpr()).map(Object::toString).orElse("") : receiver.type().asString();
        var candidates = targets(scope, receiverName, call, arguments);
        TypeInfo receiverType = receiverName.isEmpty() ? scope : types.get(qualify(receiverName, scope));
        boolean openDispatch = receiverType != null && !receiverType.isFinal && candidates.stream().noneMatch(m -> m.exact)
            && call.getScope().filter(s -> s.isObjectCreationExpr()).isEmpty();
        Value result = null;
        for (MethodInfo target : candidates) {
            if (edges.size() >= EDGE_LIMIT) throw new BudgetExceeded("JAVA_CALL_EDGE_LIMIT", "project exceeds 100000 call edges");
            edges.add((caller == null ? "<initializer>" : caller.key) + "->" + target.key);
            for (int i = 0; i < Math.min(arguments.size(), target.inputs.length); i++) {
                Value input = arguments.get(i);
                if (candidates.size() > 1 && input.nullness() == Nullness.NULL) input = new Value(input.type(), Nullness.MAYBE_NULL, input.trace(), input.parameter());
                if (input.nullness() != Nullness.UNKNOWN) {
                    Value previous = target.inputs[i];
                    Nullness state = previous.nullness() == Nullness.UNKNOWN ? input.nullness() : join(previous.nullness(), input.nullness());
                    if (state != previous.nullness()) { target.inputs[i] = new Value(SourceParsing.type(target.parameters.get(i)), state,
                        append(input.trace(), scope.path, call, "argument", target.key + " parameter " + (i + 1)), -1); changed = true; }
                }
            }
            Value value = null;
            if (target.summary != null) {
                Summary summary = target.summary;
                value = summary.parameter >= 0 && summary.parameter < arguments.size() ? arguments.get(summary.parameter)
                    : new Value(SourceParsing.type(qualifyType(target.result, target.owner)), summary.state, summary.trace, -1);
            }
            if ((value == null || value.nullness() == Nullness.UNKNOWN) && target.annotation != Nullness.UNKNOWN) value = new Value(SourceParsing.type(qualifyType(target.result, target.owner)), target.annotation,
                append(List.of(), scope.path, call, "nullable-contract", target.key), -1);
            if (value == null && !target.body && mapper(target.owner) && referenceSingle(target.result)) value = model(qualify(target.result, target.owner), scope, call, "mybatis-single-result");
            if (value == null) value = new Value(SourceParsing.type(qualifyType(target.result, target.owner)), Nullness.UNKNOWN);
            {
                value = new Value(value.type(), value.nullness(), append(value.trace(), scope.path, call, "return", target.key), value.parameter());
                result = result == null ? value : mergeValue(result, value);
            }
        }
        if (result != null) return openDispatch ? mergeValue(result, UNKNOWN) : result;
        if (receiver.type() != null && inherits(receiverName, "com.baomidou.mybatisplus.core.mapper.BaseMapper", scope)
            && ((call.getNameAsString().equals("selectById") && arguments.size() == 1)
                || call.getNameAsString().equals("selectOne") && (arguments.size() == 1 || arguments.size() == 2))) {
            TypeInfo mapper = types.get(qualify(receiverName, scope));
            String entity = "java.lang.Object";
            if (mapper != null) for (String parent : mapper.parents) if (qualify(parent, mapper).equals("com.baomidou.mybatisplus.core.mapper.BaseMapper") && parent.contains("<"))
                entity = qualify(parent.substring(parent.indexOf('<') + 1, parent.lastIndexOf('>')), mapper);
            return model(entity, scope, call, "mybatis-single-result");
        }
        if (receiver.type() != null && mapType(receiverName, scope) && call.getNameAsString().equals("get") && arguments.size() == 1) {
            String valueType = receiver.type().isClassOrInterfaceType() ? receiver.type().asClassOrInterfaceType().getTypeArguments()
                .filter(a -> a.size() == 2).map(a -> a.get(1).asString()).orElse("java.lang.Object") : "java.lang.Object";
            return model(qualify(valueType, scope), scope, call, "jdk-map-get");
        }
        if (candidates.isEmpty()) unresolved(call, scope, "call target or external return contract is unavailable");
        return UNKNOWN;
    }
    private static boolean referenceSingle(String name) {
        String raw = erase(name);
        return !Set.of("void", "boolean", "byte", "short", "int", "long", "float", "double", "char").contains(raw)
            && !name.contains("[]") && !Set.of("List", "Set", "Collection", "Map", "Optional").contains(raw.substring(raw.lastIndexOf('.') + 1));
    }
    private Value model(String type, TypeInfo owner, MethodCallExpr call, String name) {
        return new Value(SourceParsing.type(type), Nullness.MAYBE_NULL, append(List.of(), owner.path, call, "nullable-source", name), -1);
    }
    void returned(MethodInfo method, Value value, Node site, Map<MethodInfo, Value> returns) {
        if (method == null) return;
        Value located = new Value(value.type(), value.nullness(), append(value.trace(), method.owner.path, site, "return-source", method.key), value.parameter());
        returns.merge(method, located, NullDereferenceAnalyzer::mergeValue);
    }
    void finish(MethodInfo method, Value value) {
        if (method == null) return;
        analyzed.add(method.key);
        if (value == null) return;
        Summary next = new Summary(value.nullness(), value.parameter(), value.trace());
        if (method.summary == null || method.summary.state != next.state || method.summary.parameter != next.parameter) {
            method.summary = next; changed = true;
        }
    }
    void unresolved(MethodCallExpr call, TypeInfo owner, String message) {
        if (!recording || owner == null) return;
        String key = owner.path + ":" + call.getBegin().map(Object::toString).orElse("?");
        // An unknown library contract is a capability counter, not an execution failure.
        unresolved.add(key);
    }
    void diagnostic(String code, String path, Node node, String message) {
        int line = node.getBegin().map(p -> p.line).orElse(1), column = node.getBegin().map(p -> p.column).orElse(1);
        String key = code + ":" + path + ":" + line + ":" + column;
        if (diagnostics.size() < 1001) diagnostics.putIfAbsent(key, new Models.Diagnostic(code, path, line, column, message));
    }
    static List<Map<String,Object>> append(List<Map<String,Object>> previous, String path, Node node, String kind, String method) {
        var step = Map.<String,Object>of("path", path, "line", node.getBegin().map(p -> p.line).orElse(1),
            "column", node.getBegin().map(p -> p.column).orElse(1), "kind", kind, "message", method);
        if (previous.contains(step)) return previous;
        if (previous.size() >= TRACE_LIMIT) {
            if (!kind.equals("sink")) return previous;
            var shortened = new ArrayList<>(previous.subList(0, TRACE_LIMIT - 1)); shortened.add(step); return List.copyOf(shortened);
        }
        var trace = new ArrayList<>(previous); trace.add(step); return List.copyOf(trace);
    }
    static final class BudgetExceeded extends RuntimeException {
        final String code;
        BudgetExceeded(String code, String message) { super(message); this.code = code; }
    }
}
