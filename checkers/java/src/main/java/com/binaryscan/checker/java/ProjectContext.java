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
        String module = "", classSha256 = "";
        boolean external;
        boolean mapper, isInterface, isFinal, isEnum;
        List<String> imports, wildcards, parents;
        Map<String,String> typeParameters = new LinkedHashMap<>();
        Map<String, FieldInfo> fields = new LinkedHashMap<>();
        Map<String,String> guardedCaches = new LinkedHashMap<>();
        List<MethodInfo> methods = new ArrayList<>();
    }
    static final class MethodInfo {
        String key, name, result;
        TypeInfo owner;
        List<String> parameters;
        boolean isStatic, body, varargs, exact;
        boolean synchronizedMethod;
        Map<String,String> typeParameters = new LinkedHashMap<>();
        Nullness annotation = Nullness.UNKNOWN;
        final Map<String, Variant> variants = new LinkedHashMap<>();
    }
    static final class Variant {
        final String key;
        final Value[] inputs;
        Summary summary;
        int revision;
        boolean analyzed, cacheable=true;
        final Map<Variant,Integer> dependencies=new IdentityHashMap<>();
        Variant(String key, Value[] inputs) { this.key = key; this.inputs = inputs; }
    }
    record Summary(Nullness state, int parameter, List<Map<String,Object>> trace,String identity) {}
    final Map<String, TypeInfo> types = new LinkedHashMap<>();
    final Set<String> ambiguousTypes = new HashSet<>();
    final Map<String, MethodInfo> methods = new LinkedHashMap<>();
    final LinkedHashMap<String, Models.Diagnostic> diagnostics = new LinkedHashMap<>();
    final Set<String> unresolved = new HashSet<>();
    final Set<String> edges = new HashSet<>();
    final Set<String> analyzed = new HashSet<>();
    // Index-only facts: variant/nullness summaries are deliberately never cached here.
    private final Map<String,Boolean> inheritanceFacts = new HashMap<>();
    private final Map<String,List<TypeInfo>> subtypeLists = new HashMap<>();
    private int cachedSubtypeLinks;
    final Map<String,Boolean> instanceMethodFacts = new HashMap<>();
    private final Map<String,Boolean> platformFacts = new HashMap<>();
    final FrameworkContracts contracts;
    final Map<String, List<DependencyIndex.Definition>> definitions = new LinkedHashMap<>();
    SecurityAnalysis security;
    final LinkedHashMap<String, Map<String,Object>> modelProofs = new LinkedHashMap<>();
    boolean proofsTruncated;
    final long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.MINUTES.toNanos(3);
    boolean changed;
    boolean recording;
    boolean customConverterFactory;
    boolean mapperRegistryComplete;
    boolean reflectionFields;
    boolean anonymousEqualityOverride;
    final Map<String,Boolean> collectionEqualityOverrides=new HashMap<>();
    Boolean converterOverrides;
    boolean converterOverrides(){if(converterOverrides==null)converterOverrides=types.values().stream().anyMatch(t->!t.name.equals("io.github.linpeilie.Converter")&&inherits(t.name,"io.github.linpeilie.Converter",t)&&t.methods.stream().anyMatch(m->m.name.equals("convert")&&m.parameters.size()==2));return converterOverrides;}
    boolean nonstandardCollectionEquality(String type){
        if(anonymousEqualityOverride)return true;
        return collectionEqualityOverrides.computeIfAbsent(type,key->types.values().stream().filter(t->!t.external&&t.methods.stream().anyMatch(m->m.name.equals("equals")&&m.parameters.size()==1))
            .anyMatch(t->Boolean.TRUE.equals(subtype(t.name,key,t,new HashSet<>()))));
    }
    final ValidationContexts validation = new ValidationContexts(this);
    int focusedContexts;
    boolean memoize=true;
    int cachedVariantSkips, dependencyCount;
    private Variant activeVariant;
    final Map<String,List<MethodInfo>> fileMethods=new HashMap<>();
    final Set<String> initializedFiles=new HashSet<>(),initializerCalls=new HashSet<>();
    int cachedFileSkips;

    private boolean stable(Variant variant){return variant.analyzed&&variant.cacheable&&variant.dependencies.entrySet().stream().allMatch(e->e.getKey().revision==e.getValue());}
    boolean skipFile(String path){
        boolean skip=memoize&&initializedFiles.contains(path)&&!initializerCalls.contains(path)&&fileMethods.getOrDefault(path,List.of()).stream().filter(m->m.body).flatMap(m->m.variants.values().stream()).allMatch(this::stable);
        if(skip)cachedFileSkips++;return skip;
    }

    boolean begin(Variant variant){
        activeVariant=variant;
        if(recording)return true;
        if(memoize&&stable(variant)){
            cachedVariantSkips++;return false;
        }
        dependencyCount-=variant.dependencies.size();variant.dependencies.clear();return true;
    }
    void end(){activeVariant=null;}
    private Variant dependency(Variant callee){
        if(!recording&&activeVariant!=null&&activeVariant.cacheable&&!activeVariant.dependencies.containsKey(callee)){
            if(dependencyCount>=EDGE_LIMIT){dependencyCount-=activeVariant.dependencies.size();activeVariant.dependencies.clear();activeVariant.cacheable=false;}
            else{activeVariant.dependencies.put(callee,callee.revision);dependencyCount++;}
        }
        return callee;
    }

    ProjectContext() { this(new FrameworkContracts(Map.of())); }
    ProjectContext(FrameworkContracts contracts) { this.contracts = Objects.requireNonNull(contracts); }
    boolean externalContractsAllowed(String owner) { return (!types.containsKey(owner) || types.get(owner).external) && !ambiguousTypes.contains(owner); }

    void checkBudget() {
        if (Thread.currentThread().isInterrupted()) throw new BudgetExceeded("JAVA_ANALYSIS_CANCELLED", "analysis cancelled");
        if (System.nanoTime() > deadline) throw new BudgetExceeded("JAVA_TIME_LIMIT", "project analysis exceeded three minutes");
    }
    void register(String path, CompilationUnit unit) {
        if(unit.findAll(com.github.javaparser.ast.expr.ObjectCreationExpr.class).stream().anyMatch(c->c.getAnonymousClassBody().isPresent()&&c.getAnonymousClassBody().get().stream().anyMatch(m->m instanceof MethodDeclaration method&&method.getNameAsString().equals("equals")&&method.getParameters().size()==1)))anonymousEqualityOverride=true;
        if(unit.findAll(MethodCallExpr.class).stream().anyMatch(c->Set.of("getDeclaredField","getDeclaredFields","getField","getFields","setAccessible","trySetAccessible").contains(c.getNameAsString())))reflectionFields=true;
        fileMethods.putIfAbsent(path,new ArrayList<>());
        if(unit.findAll(MethodCallExpr.class).stream().anyMatch(c->c.findAncestor(MethodDeclaration.class).isEmpty()))initializerCalls.add(path);
        inheritanceFacts.clear(); subtypeLists.clear(); instanceMethodFacts.clear(); cachedSubtypeLinks=0;
        for (TypeDeclaration<?> declaration : unit.findAll(TypeDeclaration.class)) {
            TypeInfo type = new TypeInfo();
            type.packageName = unit.getPackageDeclaration().map(p -> p.getNameAsString()).orElse("");
            type.name = qualifiedName(declaration, type.packageName); type.path = path; type.isEnum = declaration.isEnumDeclaration();
            var identity = definitions.getOrDefault(type.name, List.of()).stream().filter(d -> d.matches(path)).toList();
            if (identity.size() == 1) { type.module = identity.getFirst().module(); type.classSha256 = identity.getFirst().sha256(); }
            type.imports = unit.getImports().stream().filter(i -> !i.isAsterisk() && !i.isStatic()).map(i -> i.getNameAsString()).toList();
            type.wildcards = unit.getImports().stream().filter(i -> i.isAsterisk() && !i.isStatic()).map(i -> i.getNameAsString()).toList();
            type.parents = new ArrayList<>();
            if (declaration instanceof ClassOrInterfaceDeclaration c) {
                type.isInterface = c.isInterface();
                type.isFinal = c.isFinal();
                c.getTypeParameters().forEach(p -> type.typeParameters.put(p.getNameAsString(), p.getTypeBound().isEmpty() ? "java.lang.Object" : p.getTypeBound().get(0).asString()));
                c.getExtendedTypes().forEach(p -> type.parents.add(p.asString()));
                c.getImplementedTypes().forEach(p -> type.parents.add(p.asString()));
            }
            type.mapper = declaration.getAnnotations().stream().anyMatch(a ->
                qualify(a.getNameAsString(), type).equals("org.apache.ibatis.annotations.Mapper"));
            if (declaration.findAll(com.github.javaparser.ast.expr.ObjectCreationExpr.class).stream().anyMatch(c -> qualify(c.getTypeAsString(),type).equals("io.github.linpeilie.Converter") && !c.getArguments().isEmpty())) customConverterFactory=true;
            for (FieldDeclaration field : declaration.getFields()) for (var variable : field.getVariables()) {
                Nullness state = nullable(field, type) ? Nullness.MAYBE_NULL : Nullness.UNKNOWN;
                if (variable.getInitializer().filter(e -> e.isNullLiteralExpr()).isPresent()) state = Nullness.NULL;
                type.fields.put(variable.getNameAsString(), new FieldInfo(variable.getTypeAsString(), state, field.isStatic() || type.isInterface));
                if(type.guardedCaches.size()<16&&field.isPrivate()&&field.isStatic()&&field.isFinal()&&variable.getInitializer().orElse(null) instanceof com.github.javaparser.ast.expr.ObjectCreationExpr creation
                    &&creation.getArguments().isEmpty()&&creation.getAnonymousClassBody().isEmpty()&&Set.of("java.util.HashMap","java.util.LinkedHashMap").contains(qualify(creation.getTypeAsString(),type))
                    &&guardedCacheAccesses(declaration,variable.getNameAsString()))type.guardedCaches.put(variable.getNameAsString(),qualifyType(variable.getTypeAsString(),type));
            }
            TypeInfo existing = types.get(type.name);
            if (existing != null && existing.external) { types.remove(type.name); existing = null; }
            if (existing != null && !type.classSha256.isBlank() && type.classSha256.equals(existing.classSha256)) continue;
            if (ambiguousTypes.contains(type.name) || types.putIfAbsent(type.name, type) != null) {
                ambiguousTypes.add(type.name); types.remove(type.name);
                diagnostic("JAVA_DUPLICATE_TYPE", path, declaration, "duplicate project type: " + type.name); continue;
            }
            for (var method : declaration.getMethods()) {
                if (methods.size() >= METHOD_LIMIT) throw new BudgetExceeded("JAVA_METHOD_LIMIT", "project exceeds 20000 methods");
                MethodInfo info = new MethodInfo(); info.owner = type; info.name = method.getNameAsString();
                info.result = method.getTypeAsString(); info.isStatic = method.isStatic(); info.body = method.getBody().isPresent();
                info.exact = method.isStatic() || method.isPrivate() || method.isFinal() || type.isFinal;
                info.synchronizedMethod = method.isSynchronized();
                method.getTypeParameters().forEach(p -> info.typeParameters.put(p.getNameAsString(), p.getTypeBound().isEmpty() ? "java.lang.Object" : p.getTypeBound().get(0).asString()));
                info.parameters = method.getParameters().stream().map(p -> p.getTypeAsString() + (p.isVarArgs() ? "[]" : "")).toList();
                info.varargs = !method.getParameters().isEmpty() && method.getParameter(method.getParameters().size() - 1).isVarArgs();
                info.key = type.name + "#" + info.name + "(" + String.join(",", info.parameters) + ")";
                Value[] defaults = new Value[info.parameters.size()]; Arrays.fill(defaults, UNKNOWN);
                info.variants.put("U".repeat(defaults.length), new Variant("U".repeat(defaults.length), defaults));
                if (nullable(method, type)) info.annotation = Nullness.MAYBE_NULL;
                type.methods.add(info); methods.put(info.key, info);
                fileMethods.get(path).add(info);
                validation.entries(method,info,declaration);
            }
            validation.index(declaration,type);
        }
    }
    private boolean guardedCacheAccesses(TypeDeclaration<?> declaration,String name){
        var references=new ArrayList<Node>();
        references.addAll(declaration.findAll(com.github.javaparser.ast.expr.NameExpr.class).stream().filter(n->n.getNameAsString().equals(name)).toList());
        references.addAll(declaration.findAll(com.github.javaparser.ast.expr.FieldAccessExpr.class).stream().filter(n->n.getNameAsString().equals(name)).toList());
        for(var reference:references){
            if(reference.findAncestor(com.github.javaparser.ast.expr.LambdaExpr.class).isPresent())return false;
            Node parent=reference.getParentNode().orElse(null);
            if(!(parent instanceof MethodCallExpr call)||call.getScope().orElse(null)!=reference||!Set.of("get","put","clear","remove","containsKey","containsValue","size","isEmpty","computeIfAbsent").contains(call.getNameAsString()))return false;
            var method=reference.findAncestor(MethodDeclaration.class).orElse(null);
            if(method==null||!method.isStatic()||!method.isSynchronized()||method.findAncestor(TypeDeclaration.class).orElse(null)!=declaration)return false;
        }
        return !references.isEmpty();
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
        var candidates = new ArrayList<String>();
        for (String wildcard : owner.wildcards) if (types.containsKey(wildcard + "." + raw) || platformType(wildcard+"."+raw)) candidates.add(wildcard+"."+raw);
        if (platformType("java.lang."+raw)) candidates.add("java.lang."+raw);
        candidates = new ArrayList<>(candidates.stream().distinct().toList());
        if (candidates.size() == 1) return candidates.getFirst();
        return raw;
    }
    private boolean platformType(String name) {
        if (!name.startsWith("java.")) return false;
        Boolean cached=platformFacts.get(name); if(cached!=null)return cached;
        boolean exists;
        try { Class.forName(name,false,ClassLoader.getPlatformClassLoader()); exists=true; }
        catch (ClassNotFoundException ignored) { exists=false; }
        if(platformFacts.size()<4096)platformFacts.put(name,exists);
        return exists;
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
    boolean inherits(String name, String target, TypeInfo scope) {
        String source=qualify(name,scope),parent=qualify(target,scope),key=source+"\n"+parent;
        Boolean cached=inheritanceFacts.get(key);if(cached!=null)return cached;
        boolean value=inherits(source,parent,scope,new HashSet<>());
        if(inheritanceFacts.size()<100_000)inheritanceFacts.put(key,value);
        return value;
    }
    private List<TypeInfo> subtypeCandidates(TypeInfo parent) {
        var cached=subtypeLists.get(parent.name);if(cached!=null)return cached;
        var matches=types.values().stream().filter(candidate -> !candidate.external && !candidate.isInterface && inherits(candidate.name,parent.name,candidate)).toList();
        if(subtypeLists.size()<METHOD_LIMIT && cachedSubtypeLinks+matches.size()<=100_000) {
            subtypeLists.put(parent.name,matches);cachedSubtypeLinks+=matches.size();
        }
        return matches;
    }
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
        for (String parent : type.parents) { var parentType=types.get(qualify(parent,type));var value = field(parentType, name, seen); if (value != null) {
            String specialized=value.type();if(parentType!=null)for(var b:inheritedBindings(parent,type,parentType,new HashSet<>()).entrySet())specialized=specialized.replaceAll("\\b"+java.util.regex.Pattern.quote(b.getKey())+"\\b",java.util.regex.Matcher.quoteReplacement(b.getValue()));
            return new FieldInfo(parentType==null?specialized:qualifyType(specialized,parentType),value.state(),value.isStatic());
        } }
        return null;
    }
    List<MethodInfo> targets(TypeInfo owner, String receiver, MethodCallExpr call, List<Value> arguments) {
        TypeInfo type = receiver.isEmpty() ? owner : types.get(qualify(receiver, owner));
        if (type == null) return List.of();
        List<MethodInfo> matches = new ArrayList<>(); collect(type, call.getNameAsString(), arguments.size(), matches, new HashSet<>());
        var selected=new ArrayList<Value>();for(int i=0;i<arguments.size();i++)selected.add(i<call.getArguments().size()?selectionArgument(arguments.get(i),call.getArgument(i),owner):arguments.get(i));
        matches = applicable(matches, selected, owner);
        if ((type.isInterface || matches.stream().anyMatch(m -> !m.exact)) && matches.stream().noneMatch(m -> m.exact)) {
            for (TypeInfo candidate : subtypeCandidates(type)) {
                var implementation=new ArrayList<MethodInfo>();
                collect(candidate, call.getNameAsString(), arguments.size(), implementation, new HashSet<>());
                matches.addAll(implementation);
            }
            if (matches.stream().anyMatch(m -> m.body)) matches.removeIf(m -> !m.body);
        }
        matches = new ArrayList<>(matches.stream().distinct().toList());
        matches = applicable(matches, selected, owner);
        if (matches.size() > 8) { unresolved(call, owner, "virtual call has more than eight candidate targets"); return List.of(); }
        return matches;
    }
    private void collect(TypeInfo type, String name, int arguments, List<MethodInfo> result, Set<String> seen) {
        if (type == null || !seen.add(type.name) || seen.size() > 32) return;
        var local = type.methods.stream().filter(m -> m.name.equals(name) && (m.parameters.size() == arguments || m.varargs && arguments >= m.parameters.size() - 1)).toList();
        for (var candidate : local) if (result.stream().noneMatch(existing -> existing.name.equals(candidate.name)
            && signature(existing).equals(signature(candidate)))) result.add(candidate);
        for (String parent : type.parents) collect(types.get(qualify(parent, type)), name, arguments, result, seen);
    }
    private String signature(MethodInfo method) {
        return method.parameters.stream().map(p -> qualify(p, method.owner)).collect(java.util.stream.Collectors.joining(","));
    }
    private List<MethodInfo> applicable(List<MethodInfo> methods, List<Value> arguments, TypeInfo caller) {
        Map<MethodInfo,Integer> scores = new LinkedHashMap<>();
        Set<MethodInfo> uncertain = new HashSet<>();
        for (MethodInfo method : methods) {
            int score = method.varargs ? -1 : 0; boolean possible = true;
            for (int index = 0; index < arguments.size(); index++) {
                String formal = method.parameters.get(Math.min(index, method.parameters.size() - 1));
                if (method.varargs && index >= method.parameters.size() - 1 && (!arguments.get(index).typeIsArray() || arguments.size() != method.parameters.size()))
                    formal = formal.endsWith("[]") ? formal.substring(0, formal.length() - 2) : formal;
                String bound = method.typeParameters.getOrDefault(erase(formal), method.owner.typeParameters.get(erase(formal)));
                int match = compatibility(arguments.get(index), caller, bound == null ? formal : bound, method.owner, bound != null);
                if (match == 0) uncertain.add(method);
                if (match < 0) { possible = false; break; } score += match;
            }
            if (possible) scores.put(method, score);
        }
        if (scores.isEmpty()) return new ArrayList<>();
        int best = scores.values().stream().mapToInt(Integer::intValue).max().orElse(0);
        // Specific known parameter matches win; unknowns remain candidates when equally applicable.
        return new ArrayList<>(scores.entrySet().stream().filter(e -> e.getValue() == best || uncertain.contains(e.getKey())).map(Map.Entry::getKey).toList());
    }
    private int compatibility(Value argument, TypeInfo caller, String formal, TypeInfo callee, boolean variable) {
        String target = qualifyType(formal, callee);
        if (argument.type() == null) return argument.nullness() == Nullness.NULL && primitive(target) ? -1 : 0;
        String source = qualifyType(argument.type().asString(), caller);
        String sourceRaw = rawType(source), targetRaw = rawType(target);
        if (sourceRaw.equals(targetRaw)) return variable ? 1 : 8;
        if (box(sourceRaw).equals(box(targetRaw))) return variable ? 1 : 6;
        if (primitive(sourceRaw) || primitive(targetRaw)) return numericWidening(sourceRaw, targetRaw) ? 3 : -1;
        if (targetRaw.equals("java.lang.Object")) return variable ? 1 : 2;
        if (sourceRaw.endsWith("[]") || targetRaw.endsWith("[]")) {
            if (sourceRaw.endsWith("[]") && targetRaw.endsWith("[]")) return sourceRaw.equals(targetRaw) ? 8 : 0;
            return -1;
        }
        Boolean assignable = subtype(sourceRaw, targetRaw, caller, new HashSet<>());
        return assignable == null ? 0 : assignable ? variable ? 1 : 4 : -1;
    }
    private static String rawType(String value) { return value == null ? "" : value.replaceAll("<.*>", ""); }
    private static boolean primitive(String value) { return Set.of("boolean","byte","short","char","int","long","float","double").contains(value); }
    private static String box(String value) {
        return switch (value) { case "boolean" -> "java.lang.Boolean"; case "byte" -> "java.lang.Byte"; case "short" -> "java.lang.Short";
            case "char" -> "java.lang.Character"; case "int" -> "java.lang.Integer"; case "long" -> "java.lang.Long";
            case "float" -> "java.lang.Float"; case "double" -> "java.lang.Double"; default -> value; };
    }
    private static boolean numericWidening(String source, String target) {
        return switch (source) { case "byte" -> Set.of("short","int","long","float","double").contains(target);
            case "short","char" -> Set.of("int","long","float","double").contains(target);
            case "int" -> Set.of("long","float","double").contains(target); case "long" -> Set.of("float","double").contains(target);
            case "float" -> target.equals("double"); default -> false; };
    }
    private Boolean subtype(String source, String target, TypeInfo scope, Set<String> seen) {
        source = qualify(source, scope); target = qualify(target, scope);
        if (source.equals(target) || target.equals("java.lang.Object")) return true;
        if (!seen.add(source) || seen.size() > 32) return null;
        TypeInfo type = types.get(source);
        if (type != null) {
            boolean unknown = false;
            for (String parent : type.parents) {
                Boolean relation = subtype(qualify(parent, type), target, type, seen);
                if (Boolean.TRUE.equals(relation)) return true;
                if (relation == null) unknown = true;
            }
            return unknown ? null : false;
        }
        if (source.startsWith("java.")) try {
            Class<?> knownSource = Class.forName(source, false, ClassLoader.getPlatformClassLoader());
            try { return Class.forName(target, false, ClassLoader.getPlatformClassLoader()).isAssignableFrom(knownSource); }
            catch (ClassNotFoundException absentTarget) { return false; }
        } catch (ClassNotFoundException absentSource) { return null; }
        if (source.equals("com.baomidou.mybatisplus.extension.plugins.pagination.Page")) {
            if (target.equals("com.baomidou.mybatisplus.core.metadata.IPage")) return true;
            if (Set.of("java.util.List","java.util.Map","java.util.Set","java.util.Collection").contains(target)) return false;
        }
        // A fully known project class cannot become an unrelated JDK collection by runtime casting.
        if (source.equals("java.lang.Object") || source.equals("java.io.Serializable")) return false;
        return null;
    }
    private Map<String,String> substitutions(MethodInfo target, List<Value> arguments, TypeInfo caller) {
        Map<String,String> result = new LinkedHashMap<>();
        for (int i = 0; i < Math.min(target.parameters.size(), arguments.size()); i++) if (arguments.get(i).type() != null)
            infer(target.parameters.get(i), qualifyType(arguments.get(i).type().asString(), caller), target, result);
        return result;
    }
    private void infer(String formal, String actual, MethodInfo target, Map<String,String> bindings) {
        if (target.typeParameters.containsKey(formal) || target.owner.typeParameters.containsKey(formal)) { bindings.merge(formal, actual, (a,b) -> a.equals(b) ? a : "java.lang.Object"); return; }
        Type f = SourceParsing.type(formal), a = SourceParsing.type(actual);
        if (f != null && a != null && f.isClassOrInterfaceType() && a.isClassOrInterfaceType()) {
            var formalArgs = f.asClassOrInterfaceType().getTypeArguments(); var actualArgs = a.asClassOrInterfaceType().getTypeArguments();
            if (formalArgs.isPresent() && actualArgs.isPresent() && formalArgs.get().size() == actualArgs.get().size())
                for (int i = 0; i < formalArgs.get().size(); i++) infer(formalArgs.get().get(i).asString(), actualArgs.get().get(i).asString(), target, bindings);
        }
    }
    private String resultType(MethodInfo target, List<Value> arguments, TypeInfo caller, Map<String,String> inherited) {
        String result = target.result;
        var bindings=new LinkedHashMap<>(inherited);bindings.putAll(substitutions(target, arguments, caller));
        for (var binding : bindings.entrySet()) result = result.replaceAll("\\b"+java.util.regex.Pattern.quote(binding.getKey())+"\\b", java.util.regex.Matcher.quoteReplacement(binding.getValue()));
        if (target.typeParameters.containsKey(result)) result = target.typeParameters.get(result);
        return qualifyType(result, target.owner);
    }
    String specializedReturn(MethodInfo target,List<Value> arguments,TypeInfo caller,String receiver) {
        return resultType(target,arguments,caller,inheritedBindings(receiver.isBlank()?caller.name:receiver,caller,target.owner,new HashSet<>()));
    }
    Value selectionArgument(Value actual,com.github.javaparser.ast.expr.Expression expression,TypeInfo scope){
        var enclosing=expression.findAncestor(MethodDeclaration.class).orElse(null);
        if((enclosing==null||enclosing.getTypeParameters().isEmpty())&&(scope==null||scope.typeParameters.isEmpty()))return actual;
        String declared=ExpressionFacts.declaredType(expression,expression);String bare=erase(declared),suffix="";
        while(bare.endsWith("[]")){suffix+="[]";bare=bare.substring(0,bare.length()-2);}
        String bound=null;var method=expression.findAncestor(MethodDeclaration.class).orElse(null);
        if(method!=null)for(var parameter:method.getTypeParameters())if(parameter.getNameAsString().equals(bare))bound=parameter.getTypeBound().isEmpty()?"java.lang.Object":parameter.getTypeBound().get(0).asString();
        if(bound==null&&scope!=null)bound=scope.typeParameters.get(bare);
        return bound==null?actual:actual.typed(SourceParsing.type(qualifyType(bound,scope)+suffix));
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
            var inherited = inheritedBindings(receiverName.isEmpty()?scope.name:receiverName,scope,target.owner,new HashSet<>());
            Variant variant = variant(target, arguments, scope, call, inherited);
            String specializedResult = resultType(target, arguments, scope, inherited);
            Value value = null;
            if (variant != null && variant.summary != null) {
                Summary summary = variant.summary;
                value = summary.parameter >= 0 && summary.parameter < arguments.size() ? arguments.get(summary.parameter)
                    : new Value(SourceParsing.type(specializedResult), summary.state, summary.trace, -1,summary.identity,null);
                value=value.typed(SourceParsing.type(specializedResult));
                if(summary.parameter>=0 && summary.state==Nullness.NON_NULL)value=value.state(Nullness.NON_NULL);
            }
            if ((value == null || value.nullness() == Nullness.UNKNOWN) && target.annotation != Nullness.UNKNOWN) value = new Value(SourceParsing.type(specializedResult), target.annotation,
                append(List.of(), scope.path, call, "nullable-contract", target.key), -1);
            if (value == null && !target.body && mapper(target.owner)) value = mapperResult(target, specializedResult, arguments, scope, call);
            if (value == null) value = new Value(SourceParsing.type(specializedResult), Nullness.UNKNOWN);
            {
                value = new Value(value.type(), value.nullness(), append(value.trace(), scope.path, call, "return", target.key), value.parameter(), value.objectId(), value.booleanValue());
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
    private Variant variant(MethodInfo target, List<Value> arguments, TypeInfo scope, MethodCallExpr call) {
        return variant(target,arguments,scope,call,Map.of());
    }
    private Map<String,String> inheritedBindings(String receiver,TypeInfo scope,TypeInfo target,Set<String> seen) {
        TypeInfo type=types.get(qualify(receiver,scope));if(type==null||!seen.add(type.name)||seen.size()>32)return Map.of();
        var bindings=new LinkedHashMap<String,String>();Type parsed=SourceParsing.type(receiver);
        if(parsed!=null&&parsed.isClassOrInterfaceType()){
            var args=parsed.asClassOrInterfaceType().getTypeArguments();int i=0;
            if(args.isPresent())for(String variable:type.typeParameters.keySet()){if(i<args.get().size())bindings.put(variable,qualifyType(args.get().get(i++).asString(),scope));}
        }
        if(type.name.equals(target.name))return bindings;
        for(String parent:type.parents){String p=parent;for(var b:bindings.entrySet())p=p.replaceAll("\\b"+java.util.regex.Pattern.quote(b.getKey())+"\\b",java.util.regex.Matcher.quoteReplacement(b.getValue()));
            var resolved=inheritedBindings(p,type,target,new HashSet<>(seen));if(!resolved.isEmpty())return resolved;}
        return Map.of();
    }
    private Variant variant(MethodInfo target, List<Value> arguments, TypeInfo scope, MethodCallExpr call, Map<String,String> inherited) {
        Value[] inputs = new Value[target.parameters.size()]; StringBuilder key = new StringBuilder();
        var bindings = new LinkedHashMap<>(inherited);bindings.putAll(substitutions(target, arguments, scope));
        StringBuilder typeKey = new StringBuilder();
        for (int i = 0; i < inputs.length; i++) {
            Value argument = i < arguments.size() ? arguments.get(i) : UNKNOWN;
            Nullness state = argument.nullness();
            if(primitive(target.parameters.get(i))) state=Nullness.NON_NULL;
            key.append(switch (state) { case UNKNOWN -> 'U'; case NULL -> 'N'; case NON_NULL -> 'V'; case MAYBE_NULL -> 'M'; });
            String specialized = target.parameters.get(i);
            for (var binding : bindings.entrySet()) specialized = specialized.replaceAll("\\b"+java.util.regex.Pattern.quote(binding.getKey())+"\\b",java.util.regex.Matcher.quoteReplacement(binding.getValue()));
            specialized = qualifyType(specialized, target.owner);
            if (!bindings.isEmpty()) typeKey.append('|').append(specialized);
            String identity=argument.objectId().startsWith("class:")||argument.objectId().startsWith("new:")||argument.objectId().startsWith("validated:")?argument.objectId():"";
            if(!identity.isEmpty())typeKey.append('|').append(identity);
            inputs[i] = new Value(SourceParsing.type(specialized), state,
                append(argument.trace(), scope.path, call, "argument", target.key + " parameter " + (i + 1)), i,identity,null);
        }
        key.append(typeKey);
        Variant variant = target.variants.get(key.toString());
        if (variant != null) return dependency(variant);
        int limit=target.typeParameters.isEmpty()?8:64;
        // Spend a separate finite reserve only on saturated methods whose
        // existing summaries actually carry nullable results. Stable contexts
        // remain cached by their semantic input key.
        if(target.variants.size()>=limit && target.typeParameters.isEmpty() && target.variants.size()<32 && focusedContexts<256
            && target.variants.values().stream().anyMatch(v->v.summary!=null&&(v.summary.state==Nullness.NULL||v.summary.state==Nullness.MAYBE_NULL))) {
            focusedContexts++;limit=32;
        }
        if (target.variants.size() >= limit) {
            if (recording) diagnostic("JAVA_CONTEXT_LIMIT", scope.path, call, "method exceeds "+limit+" argument/type contexts: " + target.key);
            return null;
        }
        variant = new Variant(key.toString(), inputs); target.variants.put(variant.key, variant); changed = true; return dependency(variant);
    }
    // A concrete mapper proof is separate from the library's deliberately
    // UNKNOWN scalar return contract. Custom/ambiguous factories retain UNKNOWN.
    Value mappedConversion(TypeInfo scope, String owner, MethodCallExpr call, List<Value> arguments) {
        if (!owner.equals("io.github.linpeilie.Converter") || !call.getNameAsString().equals("convert") || arguments.size()!=2
            || !externalContractsAllowed(owner)
            || arguments.getFirst().type()==null || arguments.get(1).type()==null) return null;
        var classType=arguments.get(1).type();
        if (!classType.isClassOrInterfaceType() || !qualify(classType.asClassOrInterfaceType().getNameWithScope(),scope).equals("java.lang.Class")) return null;
        var typeArgs=classType.asClassOrInterfaceType().getTypeArguments(); if(typeArgs.isEmpty()||typeArgs.get().size()!=1)return null;
        String source=qualifyType(arguments.getFirst().type().asString(),scope), destination=qualifyType(typeArgs.get().get(0).asString(),scope);
        Value selected=selectionArgument(arguments.getFirst(),call.getArgument(0),scope);
        String selectedType=selected.type()==null?"":qualifyType(selected.type().asString(),scope);
        if(Boolean.TRUE.equals(subtype(erase(selectedType),"java.util.List",scope,new HashSet<>())))return converterOverrides()?model("java.util.List<"+destination+">",scope,call,"mapstruct-overridden-list-return"):null;
        if(Boolean.TRUE.equals(subtype(erase(selectedType),"java.util.Map",scope,new HashSet<>())))return model(destination,scope,call,"mapstruct-plus-map-result");
        if(!arguments.get(1).objectId().equals("class:"+destination))return model(destination,scope,call,"mapstruct-unproven-target-class");
        if (!contracts.supports("io.github.linpeilie:mapstruct-plus")) return model(destination,scope,call,"mapstruct-unverified-scalar-return");
        if (customConverterFactory || types.values().stream().anyMatch(t -> !t.external && (inherits(t.name,owner,t) || t.parents.stream().anyMatch(p -> qualify(p,t).contains("ConverterFactory"))))) return model(destination,scope,call,"mapstruct-custom-factory-return");
        boolean exact=arguments.getFirst().objectId().startsWith("new:")||types.containsKey(erase(source))&&types.get(erase(source)).isFinal;
        if(!exact&&!mapperRegistryComplete)return model(destination,scope,call,"mapstruct-open-source-dispatch");
        if(arguments.getFirst().objectId().startsWith("new:"))source=arguments.getFirst().objectId().substring(4);
        var candidates=new ArrayList<MethodInfo>();
        for(var type:types.values()) if(!type.isInterface) {
            if(type.external&&inherits(type.name,"io.github.linpeilie.BaseMapper",type))return model(destination,scope,call,"mapstruct-external-mapper-body");
            for(var method:type.methods)if(!type.external&&method.body&&method.name.equals("convert")&&method.parameters.size()==1&&qualifyType(method.result,type).equals(destination)){
                String accepted=qualifyType(method.parameters.getFirst(),type);
                boolean compatible=accepted.equals(source)||!exact&&(inherits(accepted,source,type)||inherits(source,accepted,scope));
                if(compatible&&mapperPair(type,accepted,destination,new HashSet<>()))candidates.add(method);
            }
        }
        if(candidates.isEmpty()||candidates.size()>8||exact&&candidates.size()!=1)return model(destination,scope,call,"mapstruct-unproven-dispatch-return");
        Value result=null;
        for(MethodInfo mapper:candidates){Variant variant=variant(mapper,List.of(arguments.getFirst()),scope,call);
            if(variant==null||variant.summary==null||variant.summary.state==Nullness.UNKNOWN)return model(destination,scope,call,"mapstruct-unproven-mapper-return");
            var summary=variant.summary;Value returned=new Value(SourceParsing.type(destination),summary.state,append(summary.trace,scope.path,call,"return",mapper.key),-1);result=result==null?returned:mergeValue(result,returned);
        }
        if(result.nullness()==Nullness.NON_NULL)proof(scope.path,call,"mapstruct-plus-1.3.6-generated-mapper", "all "+candidates.size()+" compatible indexed mapper implementations prove normal return non-null for the specialized input; custom factories and missing mapper bodies are excluded");
        return result;
    }
    private boolean mapperPair(TypeInfo type,String source,String result,Set<String> seen) {
        if(type==null||!seen.add(type.name)||seen.size()>32)return false;
        for(String parent:type.parents){Type parsed=SourceParsing.type(parent);if(parsed!=null&&parsed.isClassOrInterfaceType()){
            var args=parsed.asClassOrInterfaceType().getTypeArguments();
            if(qualify(parent,type).equals("io.github.linpeilie.BaseMapper")&&args.isPresent()&&args.get().size()==2
                &&qualifyType(args.get().get(0).asString(),type).equals(source)&&qualifyType(args.get().get(1).asString(),type).equals(result))return true;
        }if(mapperPair(types.get(qualify(parent,type)),source,result,seen))return true;}
        return false;
    }
    private Value mapperResult(MethodInfo target, String result, List<Value> arguments, TypeInfo scope, MethodCallExpr call) {
        var contract = contracts.method(target.owner.name, target.name,
            arguments.stream().map(a -> a.type() == null ? "" : qualifyType(a.type().asString(), scope)).toList(), result);
        Value contracted = contractValue(contract, arguments, result, scope, call);
        if (contracted == null) contracted = contractValue(contracts.mapperReturn(result, arguments.stream()
            .map(a -> a.type()==null ? "" : qualifyType(a.type().asString(),scope)).toList()), arguments,result,scope,call);
        if (contracted != null) return contracted;
        if (subtype(rawType(result), "com.baomidou.mybatisplus.core.metadata.IPage", target.owner, new HashSet<>()) == Boolean.TRUE) return new Value(SourceParsing.type(result), Nullness.UNKNOWN);
        return referenceSingle(result) ? model(result, scope, call, "mybatis-single-result") : null;
    }
    Value contractValue(FrameworkContracts.ReturnContract contract, List<Value> arguments, String result, TypeInfo scope, MethodCallExpr call) {
        if (contract.kind() == FrameworkContracts.ReturnKind.UNKNOWN) return null;
        Type type = SourceParsing.type(result == null || result.isBlank() ? "java.lang.Object" : result);
        return switch (contract.kind()) {
            case UNKNOWN -> null;
            case NORMAL_NON_NULL -> {
                proof(scope.path, call, contract.modelId(), "normal return is non-null by the matched contract");
                yield new Value(type, Nullness.NON_NULL);
            }
            case NULLABLE -> model(type == null ? "java.lang.Object" : type.asString(), scope, call, contract.modelId());
            case PASSTHROUGH -> contract.argumentIndex() >= 0 && contract.argumentIndex() < arguments.size() ? arguments.get(contract.argumentIndex()) : UNKNOWN;
            case NULLNESS_OF_ARGUMENT -> {
                Value argument = contract.argumentIndex() >= 0 && contract.argumentIndex() < arguments.size() ? arguments.get(contract.argumentIndex()) : UNKNOWN;
                yield new Value(type, argument.nullness(), argument.trace(), argument.parameter());
            }
        };
    }
    private static boolean referenceSingle(String name) {
        String raw = erase(name);
        return !Set.of("void", "boolean", "byte", "short", "int", "long", "float", "double", "char").contains(raw)
            && !name.contains("[]") && !Set.of("List", "Set", "Collection", "Map", "Optional").contains(raw.substring(raw.lastIndexOf('.') + 1));
    }
    private Value model(String type, TypeInfo owner, MethodCallExpr call, String name) {
        return new Value(SourceParsing.type(type), Nullness.MAYBE_NULL, append(List.of(), owner.path, call, "nullable-source", name), -1);
    }
    void returned(MethodInfo method, Variant variant, Value value, Node site, Map<Variant, Value> returns) {
        if (method == null || variant == null) return;
        Value located = new Value(value.type(), value.nullness(), append(value.trace(), method.owner.path, site, "return-source", method.key), value.parameter(), value.objectId(), value.booleanValue());
        returns.merge(variant, located, NullDereferenceAnalyzer::mergeValue);
    }
    void finish(MethodInfo method, Variant variant, Value value) {
        if (method == null || variant == null) return;
        analyzed.add(method.key);
        variant.analyzed=true;
        if (value == null) return;
        String identity=value.objectId().startsWith("class:")||value.objectId().startsWith("new:")?value.objectId():"";
        Summary next = new Summary(value.nullness(), value.parameter(), value.trace(),identity);
        if (variant.summary == null || variant.summary.state != next.state || variant.summary.parameter != next.parameter || !variant.summary.identity.equals(next.identity)) {
            variant.summary = next; variant.revision++; changed = true;
        }
    }
    void proof(String path, Node node, String modelId, String condition) {
        if (!recording) return;
        int line = node.getBegin().map(p -> p.line).orElse(1), column = node.getBegin().map(p -> p.column).orElse(1);
        String key = path+":"+line+":"+column+":"+modelId+":"+condition;
        if (modelProofs.containsKey(key)) return;
        if (modelProofs.size() >= 1000) { proofsTruncated = true; return; }
        modelProofs.put(key, Map.of("path", path, "line", line, "column", column, "modelId", modelId,
            "condition", condition, "dependencyVersion", contracts.dependencyVersion(modelId)));
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
