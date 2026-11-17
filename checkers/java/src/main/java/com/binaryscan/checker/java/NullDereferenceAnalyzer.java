package com.binaryscan.checker.java;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.CallableDeclaration;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.ConstructorDeclaration;
import com.github.javaparser.ast.body.InitializerDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.TypeDeclaration;
import com.github.javaparser.ast.expr.ArrayAccessExpr;
import com.github.javaparser.ast.expr.ArrayCreationExpr;
import com.github.javaparser.ast.expr.ArrayInitializerExpr;
import com.github.javaparser.ast.expr.AssignExpr;
import com.github.javaparser.ast.expr.BinaryExpr;
import com.github.javaparser.ast.expr.BooleanLiteralExpr;
import com.github.javaparser.ast.expr.CastExpr;
import com.github.javaparser.ast.expr.ClassExpr;
import com.github.javaparser.ast.expr.ConditionalExpr;
import com.github.javaparser.ast.expr.EnclosedExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.FieldAccessExpr;
import com.github.javaparser.ast.expr.InstanceOfExpr;
import com.github.javaparser.ast.expr.LambdaExpr;
import com.github.javaparser.ast.expr.LiteralExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.expr.NullLiteralExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.expr.SuperExpr;
import com.github.javaparser.ast.expr.ThisExpr;
import com.github.javaparser.ast.expr.UnaryExpr;
import com.github.javaparser.ast.expr.VariableDeclarationExpr;
import com.github.javaparser.ast.stmt.BlockStmt;
import com.github.javaparser.ast.stmt.EmptyStmt;
import com.github.javaparser.ast.stmt.ExpressionStmt;
import com.github.javaparser.ast.stmt.IfStmt;
import com.github.javaparser.ast.stmt.ReturnStmt;
import com.github.javaparser.ast.stmt.Statement;
import com.github.javaparser.ast.stmt.SynchronizedStmt;
import com.github.javaparser.ast.stmt.ThrowStmt;
import com.github.javaparser.ast.type.ArrayType;
import com.github.javaparser.ast.type.Type;
import com.github.javaparser.ast.type.TypeParameter;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.ArrayList;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.function.Consumer;
import java.util.stream.Collectors;

/** Local nullness flow for decompiled source that may have no usable classpath. */
final class NullDereferenceAnalyzer {
    static final String MODEL_VERSION = "java-nullness-v5";
    enum Nullness { UNKNOWN, NULL, NON_NULL, MAYBE_NULL }

    private enum Sink {
        METHOD("instance-method", "实例方法接收者"),
        FIELD("instance-field", "实例字段接收者"),
        ARRAY("array-access", "数组引用"),
        ARRAY_LENGTH("array-length", "数组引用"),
        MONITOR("monitor", "同步锁"),
        METHOD_REFERENCE("method-reference", "绑定方法引用接收者"),
        UNBOX("unboxing", "自动拆箱值");

        final String kind;
        final String description;

        Sink(String kind, String description) {
            this.kind = kind;
            this.description = description;
        }
    }

    record Dereference(Node node, String message, String kind, String member, boolean uniqueOnLine,
                       List<Map<String,Object>> trace, String certainty) {}

    record Value(Type type, Nullness nullness, List<Map<String,Object>> trace, int parameter, String objectId, Boolean booleanValue) {
        Value(Type type, Nullness nullness) { this(type, nullness, List.of(), -1, "", null); }
        Value(Type type, Nullness nullness, List<Map<String,Object>> trace, int parameter) { this(type, nullness, trace, parameter, "", null); }
        boolean typeIsArray() { return type != null && type.isArrayType(); }
        Value typed(Type type) { return new Value(type, nullness, trace, parameter, objectId, booleanValue); }
        Value state(Nullness state) { return new Value(type, state, trace, parameter, objectId, booleanValue); }
    }
    private record Branch(Flow yes, Flow no) {}

    static final Value UNKNOWN = new Value(null, Nullness.UNKNOWN);
    private static final Set<String> SUPPORTED_ON_DEMAND_IMPORTS = Set.of("java.lang", "java.io", "java.util");
    private record MethodKind(int arity, boolean varArgs, boolean isStatic) {
        private boolean accepts(int arguments) {
            return varArgs ? arguments >= arity - 1 : arguments == arity;
        }
    }

    private static final Map<String, Map<String, List<MethodKind>>> JDK_METHODS = List.of(
        Object.class, CharSequence.class, String.class, StringBuilder.class, StringBuffer.class,
        Boolean.class, Byte.class, Character.class, Short.class, Integer.class,
        Long.class, Float.class, Double.class, java.io.File.class,
        java.util.Collection.class, java.util.List.class, java.util.Map.class,
        java.util.Set.class, java.util.Optional.class
    ).stream().collect(Collectors.toUnmodifiableMap(Class::getName, type ->
        List.of(type.getMethods()).stream().collect(Collectors.groupingBy(Method::getName,
            Collectors.mapping(method -> new MethodKind(method.getParameterCount(), method.isVarArgs(),
                Modifier.isStatic(method.getModifiers())), Collectors.toList())))));

    private final CompilationUnit unit;
    private final List<TypeDeclaration<?>> types;
    private final List<TypeParameter> typeParameters;
    private final Consumer<Dereference> emit;
    private final int[] dereferencesByLine;
    private final ProjectContext project;
    private final String path;
    private ProjectContext.MethodInfo currentMethod;
    private ProjectContext.Variant currentVariant;
    private ProjectContext.TypeInfo currentType;
    private final Map<ProjectContext.Variant, Value> returns = new HashMap<>();
    private final Deque<List<Value>> yields = new ArrayDeque<>();
    private static final class ControlFrame {
        Flow breaks, continues;
    }
    private static final class ExceptionFrame { Flow state; }
    private final Deque<ControlFrame> breakFrames = new ArrayDeque<>();
    private final Deque<ControlFrame> loopFrames = new ArrayDeque<>();
    private final Deque<ExceptionFrame> exceptionFrames = new ArrayDeque<>();
    private static final class MapState {
        boolean owned = true, allNonNull = true, unknownKeys;
        final Map<String,Value> entries = new HashMap<>();
        final Set<String> present = new java.util.HashSet<>();
        MapState copy() { var copy = new MapState(); copy.owned=owned; copy.allNonNull=allNonNull; copy.unknownKeys=unknownKeys; copy.entries.putAll(entries); copy.present.addAll(present); return copy; }
        void escape() { owned=false; allNonNull=false; unknownKeys=true; entries.clear(); present.clear(); }
    }

    private NullDereferenceAnalyzer(CompilationUnit unit, Consumer<Dereference> emit) {
        this(unit, emit, null, "");
    }

    private NullDereferenceAnalyzer(CompilationUnit unit, Consumer<Dereference> emit, ProjectContext project, String path) {
        this.unit = unit;
        this.emit = emit;
        this.types = unit.findAll(TypeDeclaration.class).stream()
            .<TypeDeclaration<?>>map(declaration -> declaration).toList();
        this.typeParameters = unit.findAll(TypeParameter.class);
        this.dereferencesByLine = countDereferenceSpans(unit);
        this.project = project;
        this.path = path;
    }

    static void analyze(CompilationUnit unit, Consumer<Dereference> emit) {
        analyze(unit, emit, null, "");
    }

    static void analyze(CompilationUnit unit, Consumer<Dereference> emit, ProjectContext project, String path) {
        var analyzer = new NullDereferenceAnalyzer(unit, emit, project, path);
        unit.findAll(MethodDeclaration.class).forEach(method ->
            method.getBody().ifPresent(body -> analyzer.callable(method, body)));
        unit.findAll(ConstructorDeclaration.class).forEach(constructor ->
            analyzer.callable(constructor, constructor.getBody()));
        unit.findAll(InitializerDeclaration.class).forEach(initializer ->
            analyzer.statement(initializer.getBody(), new Flow()));
    }

    private static int[] countDereferenceSpans(CompilationUnit unit) {
        int[] counts = new int[unit.getEnd().map(position -> position.line).orElse(0) + 2];
        // Include sites that did not produce a finding and expressions spanning several lines.
        unit.walk(node -> {
            if (!(node instanceof MethodCallExpr || node instanceof FieldAccessExpr
                || node instanceof ArrayAccessExpr || node instanceof SynchronizedStmt)) return;
            var start = node.getBegin();
            var end = node instanceof SynchronizedStmt sync ? sync.getExpression().getEnd() : node.getEnd();
            if (start.isPresent() && end.isPresent() && end.get().line + 1 < counts.length) {
                counts[start.get().line]++;
                counts[end.get().line + 1]--;
            }
        });
        for (int line = 1; line < counts.length; line++) counts[line] += counts[line - 1];
        return counts;
    }

    private void callable(CallableDeclaration<?> callable, BlockStmt body) {
        if (project != null) {
            project.checkBudget();
            currentType = project.owner(callable, unit);
            currentMethod = project.method(callable, unit);
        }
        if (currentMethod != null) {
            for (var variant : List.copyOf(currentMethod.variants.values())) {
                currentVariant = variant;
                if(project.begin(variant))callableBody(callable, body);
                project.end();
            }
        } else { currentVariant = null; callableBody(callable, body); }
    }
    private void callableBody(CallableDeclaration<?> callable, BlockStmt body) {
        Flow flow = new Flow();
        if(project!=null&&currentType!=null&&currentMethod!=null&&currentMethod.isStatic&&currentMethod.synchronizedMethod&&!project.reflectionFields
            &&project.externalContractsAllowed("java.util.HashMap")&&project.externalContractsAllowed("java.util.LinkedHashMap")){
            for(var cache:currentType.guardedCaches.entrySet()){
                String id="private-cache:"+currentType.name+"#"+cache.getKey();var state=new MapState();state.unknownKeys=true;state.allNonNull=false;flow.maps.put(id,state);
                flow.locals.put(cache.getKey(),new Value(SourceParsing.type(cache.getValue()),Nullness.NON_NULL,List.of(),-1,id,null));
                project.proof(path,callable,"core-private-cache-monitor","private final JDK map has no visible escape; all indexed accesses share this class monitor; contents are unknown on method entry and unknown calls invalidate content facts");
            }
        }
        for (int index = 0; index < callable.getParameters().size(); index++) {
            var parameter = callable.getParameter(index);
            Value input = currentVariant == null ? UNKNOWN : currentVariant.inputs[index];
            if (project != null && input.nullness() == Nullness.UNKNOWN && project.nullableAnnotations(parameter.getAnnotations(), currentType))
                input = new Value(parameter.getType(), Nullness.MAYBE_NULL,
                    ProjectContext.append(List.of(), path, parameter, "nullable-source", "nullable parameter contract"), index);
            Type specialized = input.type() == null ? (parameter.isVarArgs() ? new ArrayType(parameter.getType().clone()) : parameter.getType()) : input.type();
            flow.locals.put(parameter.getNameAsString(), new Value(specialized, input.nullness(), input.trace(), index, input.objectId(), input.booleanValue()));
        }
        statement(body, flow);
        if (project != null) project.finish(currentMethod, currentVariant, returns.get(currentVariant));
    }

    private void statement(Statement statement, Flow flow) {
        if (project != null) project.checkBudget();
        if (!flow.reachable) return;
        switch (statement) {
            case BlockStmt block -> {
                var outerNames = List.copyOf(flow.locals.keySet());
                block.getStatements().forEach(child -> statement(child, flow));
                flow.locals.keySet().retainAll(outerNames);
            }
            case ExpressionStmt expression -> value(expression.getExpression(), flow);
            case IfStmt conditional -> {
                Branch branch = condition(conditional.getCondition(), flow);
                statement(conditional.getThenStmt(), branch.yes());
                conditional.getElseStmt().ifPresent(otherwise -> statement(otherwise, branch.no()));
                Flow merged = Flow.merge(branch.yes(), branch.no());
                Expression test = unwrap(conditional.getCondition());
                if (test instanceof NameExpr name && flow.locals.containsKey(name.getNameAsString())
                    && conditional.findAll(AssignExpr.class).stream().noneMatch(a -> a.getTarget().toString().equals(name.getNameAsString()))) {
                    merged.remember(name.getNameAsString(), true, branch.yes());
                    merged.remember(name.getNameAsString(), false, branch.no());
                }
                flow.replaceWith(merged);
            }
            case ReturnStmt returned -> {
                returned.getExpression().ifPresent(expression -> {
                    Value result = value(expression, flow);
                    if (currentMethod != null && SourceParsing.type(currentMethod.result).isPrimitiveType()) unbox(returned, expression, result, flow);
                    if (project != null) project.returned(currentMethod, currentVariant, result, returned, returns);
                });
                flow.reachable = false;
            }
            case ThrowStmt thrown -> {
                captureExceptions(flow);
                value(thrown.getExpression(), flow);
                flow.reachable = false;
            }
            case SynchronizedStmt sync -> {
                captureExceptions(flow);
                Expression lock = sync.getExpression();
                dereference(sync, lock, value(lock, flow), flow, Sink.MONITOR);
                statement(sync.getBody(), flow);
            }
            case EmptyStmt ignored -> { }
            case com.github.javaparser.ast.stmt.ExplicitConstructorInvocationStmt constructor -> {
                constructor.getExpression().ifPresent(e -> value(e, flow));
                constructor.getArguments().forEach(e -> escape(value(e, flow),flow));
                if (project != null && project.recording) project.unresolved.add(path + ":constructor:" + constructor.getBegin().orElse(null));
            }
            case com.github.javaparser.ast.stmt.WhileStmt loop -> loop(loop.getCondition(), loop.getBody(), flow, false);
            case com.github.javaparser.ast.stmt.DoStmt loop -> loop(loop.getCondition(), loop.getBody(), flow, true);
            case com.github.javaparser.ast.stmt.ForStmt loop -> {
                loop.getInitialization().forEach(e -> value(e, flow));
                loop(loop.getCompare().orElse(new BooleanLiteralExpr(true)), loop.getBody(), flow, false, loop.getUpdate());
            }
            case com.github.javaparser.ast.stmt.ForEachStmt loop -> {
                Value iterable = value(loop.getIterable(), flow);
                dereference(loop, loop.getIterable(), iterable, flow, Sink.ARRAY);
                Flow iteration = flow.copy(); value(loop.getVariable(), iteration);
                var frame = new ControlFrame(); breakFrames.push(frame); loopFrames.push(frame);
                statement(loop.getBody(), iteration); loopFrames.pop(); breakFrames.pop();
                Flow exit = mergeReachable(flow, mergeReachable(iteration, mergeReachable(frame.breaks, frame.continues)));
                flow.replaceWith(exit);
            }
            case com.github.javaparser.ast.stmt.TryStmt tried -> tryStatement(tried, flow);
            case com.github.javaparser.ast.stmt.SwitchStmt switched -> {
                value(switched.getSelector(), flow);
                var frame = new ControlFrame(); breakFrames.push(frame);
                Flow merged = null;
                for (var entry : switched.getEntries()) {
                    Flow branch = flow.copy(); entry.getStatements().forEach(child -> statement(child, branch));
                    branch.reachable = true; merged = merged == null ? branch : Flow.merge(merged, branch);
                }
                if (merged != null) flow.replaceWith(switched.getEntries().stream().anyMatch(e -> e.getLabels().isEmpty()) ? merged : Flow.merge(flow, merged));
                breakFrames.pop();
            }
            case com.github.javaparser.ast.stmt.YieldStmt yielded -> {
                Value result = value(yielded.getExpression(), flow);
                if (!yields.isEmpty()) yields.peek().add(result);
                flow.reachable = false;
            }
            case com.github.javaparser.ast.stmt.BreakStmt broken -> {
                if (broken.getLabel().isPresent() && project != null && project.recording) project.diagnostic("JAVA_LABELED_CONTROL_FLOW", path, broken, "labeled break requires conservative control-flow handling");
                if (!breakFrames.isEmpty()) breakFrames.peek().breaks = mergeReachable(breakFrames.peek().breaks, flow);
                flow.reachable = false;
            }
            case com.github.javaparser.ast.stmt.ContinueStmt continued -> {
                if (continued.getLabel().isPresent() && project != null && project.recording) project.diagnostic("JAVA_LABELED_CONTROL_FLOW", path, continued, "labeled continue requires conservative control-flow handling");
                if (!loopFrames.isEmpty()) loopFrames.peek().continues = mergeReachable(loopFrames.peek().continues, flow);
                flow.reachable = false;
            }
            case com.github.javaparser.ast.stmt.LabeledStmt labeled -> statement(labeled.getStatement(), flow);
            case com.github.javaparser.ast.stmt.AssertStmt assertion -> {
                value(assertion.getCheck(), flow); assertion.getMessage().ifPresent(e -> value(e, flow));
                // JVM assertions may be disabled; do not use them as a non-null contract.
            }
            // Unsupported control flow may change any previously tracked value.
            default -> {
                if (project != null && project.recording) project.diagnostic("JAVA_UNSUPPORTED_CONTROL_FLOW", path, statement,
                    "unsupported statement: " + statement.getClass().getSimpleName());
                flow.forgetValues();
            }
        }
    }

    private void loop(Expression test, Statement body, Flow flow, boolean atLeastOnce) {
        loop(test, body, flow, atLeastOnce, List.of());
    }
    private void loop(Expression test, Statement body, Flow flow, boolean atLeastOnce, List<Expression> updates) {
        Flow entry = flow.copy(), head = flow.copy();
        Flow exits = null;
        for (int round = 0; round < 4; round++) {
            Branch branch;
            if (atLeastOnce && round == 0) { Flow no = head.copy(); no.reachable = false; branch = new Branch(head.copy(), no); }
            else branch = condition(test, head);
            exits = mergeReachable(exits, branch.no());
            var frame = new ControlFrame(); breakFrames.push(frame); loopFrames.push(frame);
            statement(body, branch.yes()); loopFrames.pop(); breakFrames.pop();
            exits = mergeReachable(exits, frame.breaks);
            Flow continuing = mergeReachable(branch.yes(), frame.continues);
            if (continuing == null) break;
            updates.forEach(update -> value(update, continuing));
            Flow next = atLeastOnce && round == 0 ? continuing : Flow.merge(entry, continuing);
            if (sameStates(head, next)) { head = next; break; }
            head = next;
            if (round == 3 && project != null && project.recording) project.diagnostic("JAVA_LOOP_WIDENED", path, body,
                "loop analysis reached the four-iteration bound");
        }
        if (exits == null) flow.reachable = false; else flow.replaceWith(exits);
    }
    private static Flow mergeReachable(Flow left, Flow right) {
        if (right == null || !right.reachable) return left == null ? null : left.copy();
        if (left == null || !left.reachable) return right.copy();
        return Flow.merge(left, right);
    }
    private static boolean sameStates(Flow left, Flow right) {
        return left.locals.keySet().equals(right.locals.keySet()) && left.locals.entrySet().stream()
            .allMatch(e -> e.getValue().nullness() == right.locals.get(e.getKey()).nullness()
                && Objects.equals(e.getValue().booleanValue(),right.locals.get(e.getKey()).booleanValue())
                && e.getValue().objectId().equals(right.locals.get(e.getKey()).objectId()))
            && left.assumptions.equals(right.assumptions) && left.branches.equals(right.branches)
            && left.maps.keySet().equals(right.maps.keySet()) && left.maps.entrySet().stream().allMatch(e -> {
                var other=right.maps.get(e.getKey()); var value=e.getValue();
                return value.owned==other.owned && value.allNonNull==other.allNonNull && value.unknownKeys==other.unknownKeys
                    && value.present.equals(other.present) && value.entries.keySet().equals(other.entries.keySet())
                    && value.entries.entrySet().stream().allMatch(v -> v.getValue().nullness()==other.entries.get(v.getKey()).nullness());
            });
    }
    private void tryStatement(com.github.javaparser.ast.stmt.TryStmt tried, Flow flow) {
        Value priorReturns = returns.get(currentVariant);
        var exceptional = new ExceptionFrame(); exceptionFrames.push(exceptional);
        tried.getResources().forEach(e -> value(e, flow));
        Flow normal = flow.copy(); statement(tried.getTryBlock(), normal);
        if (!tried.getResources().isEmpty()) captureExceptions(normal);
        exceptionFrames.pop();
        Flow merged = normal;
        for (var caught : tried.getCatchClauses()) {
            if (exceptional.state == null) continue;
            Flow branch = exceptional.state.copy(); branch.reachable = true;
            branch.locals.put(caught.getParameter().getNameAsString(), new Value(caught.getParameter().getType(), Nullness.NON_NULL));
            statement(caught.getBody(), branch); merged = Flow.merge(merged, branch);
        }
        flow.replaceWith(merged);
        tried.getFinallyBlock().ifPresent(block -> {
            if (!block.getStatements().isEmpty() && (block.getStatement(block.getStatements().size() - 1).isReturnStmt()
                || block.getStatement(block.getStatements().size() - 1).isThrowStmt())) {
                if (priorReturns == null) returns.remove(currentVariant); else returns.put(currentVariant, priorReturns);
            }
            boolean reachable = flow.reachable; flow.reachable = true; statement(block, flow);
            flow.reachable = reachable && flow.reachable;
        });
    }

    private Value value(Expression expression, Flow flow) {
        if (!flow.reachable) return UNKNOWN;
        if (expression instanceof MethodCallExpr || expression instanceof ObjectCreationExpr || expression instanceof FieldAccessExpr
            || expression instanceof ArrayAccessExpr || expression instanceof CastExpr || expression instanceof BinaryExpr) captureExceptions(flow);
        return switch (expression) {
            case NullLiteralExpr literal -> new Value(null, Nullness.NULL,
                project == null ? List.of() : ProjectContext.append(List.of(), path, literal, "nullable-source", "explicit null"), -1);
            case NameExpr name -> localOrField(name.getNameAsString(), flow);
            case EnclosedExpr enclosed -> value(enclosed.getInner(), flow);
            case CastExpr cast -> {
                Value operand = value(cast.getExpression(), flow);
                if (cast.getType().isPrimitiveType()) unbox(cast, cast.getExpression(), operand, flow);
                yield new Value(cast.getType(), cast.getType().isPrimitiveType() ? Nullness.UNKNOWN : operand.nullness(), operand.trace(), operand.parameter(), operand.objectId(), operand.booleanValue());
            }
            case VariableDeclarationExpr declaration -> {
                declaration.getVariables().forEach(variable -> {
                    Value initial = variable.getInitializer().map(expr -> value(expr, flow)).orElse(UNKNOWN);
                    Type type = variable.getType().isVarType() ? initial.type() : variable.getType();
                    if (type != null && type.isPrimitiveType()) variable.getInitializer().ifPresent(initializer -> unbox(variable, initializer, initial, flow));
                    flow.invalidate(variable.getNameAsString()); flow.locals.put(variable.getNameAsString(), initial.typed(type));
                });
                yield UNKNOWN;
            }
            case AssignExpr assignment -> assign(assignment, flow);
            case MethodCallExpr call -> call(call, flow);
            case FieldAccessExpr field -> access(field, field.getScope(), null, flow);
            case ArrayAccessExpr array -> access(array, array.getName(), null, flow);
            case ConditionalExpr conditional -> {
                Branch branch = condition(conditional.getCondition(), flow);
                Value yes = value(conditional.getThenExpr(), branch.yes());
                Value no = value(conditional.getElseExpr(), branch.no());
                Value result = !branch.yes().reachable ? no : !branch.no().reachable ? yes
                    : mergeValue(yes, no);
                flow.replaceWith(Flow.merge(branch.yes(), branch.no()));
                yield result;
            }
            case BinaryExpr binary -> {
                if (binary.getOperator() == BinaryExpr.Operator.AND || binary.getOperator() == BinaryExpr.Operator.OR) {
                    Branch branch = condition(binary, flow);
                    flow.replaceWith(Flow.merge(branch.yes(), branch.no()));
                } else {
                    value(binary.getLeft(), flow);
                    value(binary.getRight(), flow);
                }
                yield UNKNOWN;
            }
            case UnaryExpr unary -> {
                Value operand = value(unary.getExpression(), flow);
                unbox(unary, unary.getExpression(), operand, flow);
                if (Set.of(UnaryExpr.Operator.POSTFIX_INCREMENT,UnaryExpr.Operator.POSTFIX_DECREMENT,UnaryExpr.Operator.PREFIX_INCREMENT,UnaryExpr.Operator.PREFIX_DECREMENT).contains(unary.getOperator())) {
                    String target=unwrap(unary.getExpression()).toString();flow.invalidate(target);
                    if (flow.locals.containsKey(target)) flow.locals.put(target,new Value(operand.type(),operand.nullness()));
                }
                yield UNKNOWN;
            }
            case InstanceOfExpr test -> {
                value(test.getExpression(), flow);
                yield UNKNOWN;
            }
            case ObjectCreationExpr creation -> {
                invalidatePrivateCaches(flow);
                creation.getScope().ifPresent(scope -> value(scope, flow));
                creation.getArguments().forEach(argument -> escape(value(argument, flow),flow));
                if (project != null && currentType != null && creation.getAnonymousClassBody().isEmpty()
                    && Set.of("java.util.HashMap","java.util.LinkedHashMap","java.util.TreeMap","java.util.concurrent.ConcurrentHashMap")
                        .contains(project.qualify(creation.getType().asString(), currentType)) && creation.getArguments().isEmpty()) {
                    String id = path+"@"+creation.getBegin().map(Object::toString).orElse("map");
                    if (flow.maps.size() < 256) {
                        flow.maps.put(id, new MapState());
                        yield new Value(creation.getType(), Nullness.NON_NULL, List.of(), -1, id, null);
                    }
                    if (project.recording) project.diagnostic("JAVA_MAP_FACT_LIMIT",path,creation,"method exceeds 256 owned map facts");
                }
                yield new Value(creation.getType(), Nullness.NON_NULL,List.of(),-1,"new:"+(project==null?creation.getTypeAsString():project.qualifyType(creation.getTypeAsString(),currentType)),null);
            }
            case ArrayCreationExpr array -> {
                array.getLevels().forEach(level -> level.getDimension().ifPresent(dimension -> value(dimension, flow)));
                array.getInitializer().ifPresent(initializer -> value(initializer, flow));
                yield new Value(array.createdType(), Nullness.NON_NULL);
            }
            case ArrayInitializerExpr initializer -> {
                initializer.getValues().forEach(element -> escape(value(element, flow),flow));
                yield new Value(null, Nullness.NON_NULL);
            }
            case com.github.javaparser.ast.expr.StringLiteralExpr ignored -> new Value(SourceParsing.type("java.lang.String"), Nullness.NON_NULL);
            case com.github.javaparser.ast.expr.IntegerLiteralExpr ignored -> new Value(SourceParsing.type("int"), Nullness.NON_NULL);
            case BooleanLiteralExpr literal -> new Value(SourceParsing.type("boolean"), Nullness.NON_NULL, List.of(), -1, "", literal.getValue());
            case LiteralExpr ignored -> new Value(null, Nullness.NON_NULL);
            case ThisExpr ignored -> new Value(null, Nullness.NON_NULL);
            case SuperExpr ignored -> new Value(null, Nullness.NON_NULL);
            case LambdaExpr lambda -> {
                for (NameExpr captured : lambda.findAll(NameExpr.class)) if (flow.locals.containsKey(captured.getNameAsString())) escape(flow.locals.get(captured.getNameAsString()),flow);
                Flow closure = flow.copy();
                lambda.getParameters().forEach(p -> closure.locals.put(p.getNameAsString(), new Value(p.getType(), Nullness.UNKNOWN)));
                var enclosing = currentMethod; var enclosingVariant = currentVariant; currentMethod = null; currentVariant = null;
                statement(lambda.getBody(), closure); currentMethod = enclosing; currentVariant = enclosingVariant;
                yield new Value(null, Nullness.NON_NULL);
            }
            case com.github.javaparser.ast.expr.MethodReferenceExpr reference -> {
                // JavaParser may parse an expression-name receiver as TypeExpr
                // (m::clear). Resolve locally before treating it as a type name.
                boolean boundName=reference.getScope().isTypeExpr() && (flow.locals.containsKey(reference.getScope().toString())
                    || project!=null && currentType!=null && project.field(currentType,reference.getScope().toString())!=null);
                if (!reference.getScope().isTypeExpr() || boundName) {
                    Value receiver = boundName ? localOrField(reference.getScope().toString(),flow) : value(reference.getScope(), flow);
                    escape(receiver,flow);
                    dereference(reference, reference.getScope(), receiver, flow, Sink.METHOD_REFERENCE);
                }
                yield new Value(null, Nullness.NON_NULL);
            }
            case com.github.javaparser.ast.expr.SwitchExpr switched -> {
                value(switched.getSelector(), flow);
                var results = new ArrayList<Value>(); yields.push(results);
                Flow merged = null;
                for (var entry : switched.getEntries()) {
                    Flow branch = flow.copy();
                    for (var statement : entry.getStatements()) {
                        if (entry.getType() == com.github.javaparser.ast.stmt.SwitchEntry.Type.EXPRESSION && statement.isExpressionStmt())
                            results.add(value(statement.asExpressionStmt().getExpression(), branch));
                        else statement(statement, branch);
                    }
                    branch.reachable = true; merged = merged == null ? branch : Flow.merge(merged, branch);
                }
                yields.pop(); if (merged != null) flow.replaceWith(merged);
                yield results.stream().reduce(NullDereferenceAnalyzer::mergeValue).orElse(UNKNOWN);
            }
            case com.github.javaparser.ast.expr.TypeExpr ignored -> new Value(null, Nullness.NON_NULL);
            case ClassExpr literal -> {
                String target=project==null?literal.getType().asString():project.qualifyType(literal.getType().asString(),currentType);
                yield new Value(SourceParsing.type("java.lang.Class<"+target+">"),Nullness.NON_NULL,List.of(),-1,"class:"+target,null);
            }
            default -> {
                if (project != null && project.recording) project.diagnostic("JAVA_UNSUPPORTED_EXPRESSION", path, expression,
                    "unsupported expression: " + expression.getClass().getSimpleName());
                flow.forgetValues();
                yield UNKNOWN;
            }
        };
    }

    private Value assign(AssignExpr assignment, Flow flow) {
        Expression target = unwrap(assignment.getTarget());
        boolean simple = assignment.getOperator() == AssignExpr.Operator.ASSIGN;
        if (simple && target instanceof FieldAccessExpr field) {
            return access(field, field.getScope(), assignment.getValue(), flow);
        }
        if (simple && target instanceof ArrayAccessExpr array) {
            return access(array, array.getName(), assignment.getValue(), flow);
        }
        if (!simple) value(target, flow);
        Value assigned = value(assignment.getValue(), flow);
        if (target instanceof NameExpr name) {
            Value previous = flow.locals.get(name.getNameAsString());
            if (previous != null) {
                flow.invalidate(name.getNameAsString());
                Value updated = simple ? assigned.typed(previous.type()) : new Value(previous.type(),Nullness.UNKNOWN);
                flow.locals.put(name.getNameAsString(), updated);
                return updated;
            }
            if (project != null && currentType != null) {
                var field = project.field(currentType, name.getNameAsString());
                if (field != null) {
                    escape(assigned,flow);flow.invalidate("this."+name.getNameAsString());
                    Value updated = new Value(SourceParsing.type(project.qualifyType(field.type(), currentType)), assigned.nullness(), assigned.trace(), assigned.parameter());
                    flow.locals.put("this." + name.getNameAsString(), updated); return updated;
                }
            }
        }
        if (!(target instanceof NameExpr)) flow.invalidate(target.toString());
        return UNKNOWN;
    }
    private static void escape(Value value,Flow flow) {
        if (!value.objectId().isEmpty() && flow.maps.containsKey(value.objectId())) flow.maps.get(value.objectId()).escape();
        if(value.objectId().startsWith("validated:")){
            flow.validations.clear();
            flow.locals.replaceAll((key,v)->v.objectId().startsWith("validated:")?new Value(v.type(),v.nullness(),v.trace(),v.parameter()):v);
        }
    }

    private Value call(MethodCallExpr call, Flow flow) {
        Expression scope = call.getScope().orElse(null);
        Value receiver = scope == null ? UNKNOWN : value(scope, flow);
        List<Value> arguments = call.getArguments().stream().map(argument -> value(argument, flow)).toList();
        boolean privateOperation=receiver.objectId().startsWith("private-cache:")&&(
            Set.of("size","isEmpty","clear").contains(call.getNameAsString())&&arguments.isEmpty()
            ||!arguments.isEmpty()&&stableKey(call.getArgument(0),flow)!=null&&Set.of("get","put","remove","containsKey").contains(call.getNameAsString()));
        if(!privateOperation)invalidatePrivateCaches(flow);
        captureExceptions(flow);
        if (receiver.nullness() != Nullness.NON_NULL && isInstanceMethod(receiver.type(), call)) {
            dereference(call, scope, receiver, flow, Sink.METHOD);
        }
        if (call.getNameAsString().equals("requireNonNull") && (arguments.size() == 1 || arguments.size() == 2)
            && isObjectsCall(call, flow)) {
            Value checked = arguments.getFirst();
            if (checked.nullness() == Nullness.NULL) flow.reachable = false;
            refine(call.getArgument(0), checked, Nullness.NON_NULL, flow);
            if(project!=null)project.proof(path,call,"jdk21-require-non-null","normal return verifies the argument is non-null");
            return checked.state(Nullness.NON_NULL);
        }
        if (project != null && !arguments.isEmpty() && Set.of("notNull", "checkNotNull").contains(call.getNameAsString())
            && trustedUtility(call, Set.of("org.springframework.util.Assert", "cn.hutool.core.lang.Assert", "com.google.common.base.Preconditions"), flow)) {
            Value checked = arguments.getFirst();
            if (checked.nullness() == Nullness.NULL) flow.reachable = false;
            refine(call.getArgument(0), checked, Nullness.NON_NULL, flow);
            return checked.state(Nullness.NON_NULL);
        }
        if (project != null && currentType != null) {
            String callOwner=utilityOwner(call,receiver,flow);
            if(project.contracts.exact("cn.dev33:sa-token-core","1.37.0")&&project.externalContractsAllowed(callOwner)){
                if(callOwner.equals("cn.dev33.satoken.context.SaHolder")&&call.getNameAsString().equals("getStorage")&&arguments.isEmpty()){
                    String id="request-storage:"+call.getBegin();var state=new MapState();state.unknownKeys=true;state.allNonNull=false;flow.maps.putIfAbsent(id,state);
                    return new Value(SourceParsing.type("cn.dev33.satoken.context.model.SaStorage"),Nullness.UNKNOWN,List.of(),-1,id,null);
                }
                if(callOwner.equals("cn.dev33.satoken.context.model.SaStorage")){
                    var state=flow.maps.get(receiver.objectId());String key=arguments.isEmpty()?null:stableKey(call.getArgument(0),flow);
                    if(call.getNameAsString().equals("set")&&arguments.size()==2){if(state!=null&&state.owned){invalidateAliasingKeys(state,key);if(key!=null)state.entries.put(key,arguments.get(1));}return receiver;}
                    if(call.getNameAsString().equals("delete")&&state!=null){invalidateAliasingKeys(state,key);if(key!=null)state.entries.remove(key);return receiver;}
                    if(call.getNameAsString().equals("get")&&arguments.size()==1){Value stored=state==null||!state.owned||key==null?null:state.entries.get(key);if(stored!=null){if(stored.nullness()==Nullness.NON_NULL)project.proof(path,call,"sa-token-1.37-request-write-read","same request storage object and key, non-null write, no intervening unknown call or delete; does not establish cross-request login user state");return stored;}return new Value(SourceParsing.type("java.lang.Object"),Nullness.MAYBE_NULL,ProjectContext.append(List.of(),path,call,"nullable-source","request storage key has no proven non-null value"),-1);}
                }
                if(callOwner.equals("cn.dev33.satoken.session.SaSession")&&call.getNameAsString().equals("get")&&arguments.size()==1)return new Value(SourceParsing.type("java.lang.Object"),Nullness.MAYBE_NULL,ProjectContext.append(List.of(),path,call,"nullable-source","login/session existence does not prove this user-data key is populated"),-1);
            }
            if(project.externalContractsAllowed(callOwner)&&Set.of("jakarta.validation.Validator","javax.validation.Validator").contains(callOwner)&&call.getNameAsString().equals("validate")&&!arguments.isEmpty()&&call.getArgument(0) instanceof NameExpr object){
                var groups=new java.util.TreeSet<String>();for(int i=1;i<call.getArguments().size();i++)if(call.getArgument(i) instanceof ClassExpr group)groups.add(project.qualify(group.getTypeAsString(),currentType));
                if(groups.isEmpty())groups.add("jakarta.validation.groups.Default");
                String id="violations:"+call.getBegin();flow.validations.put(id,new ValidationState(object.getNameAsString(),flow.generations.getOrDefault(object.getNameAsString(),0),Set.copyOf(groups)));
                return new Value(SourceParsing.type("java.util.Set"),Nullness.NON_NULL,List.of(),-1,id,null);
            }
            if(receiver.objectId().startsWith("violations:")&&Set.of("isEmpty","size").contains(call.getNameAsString())&&arguments.isEmpty())return new Value(SourceParsing.type(call.getNameAsString().equals("isEmpty")?"boolean":"int"),Nullness.NON_NULL);
            flow.forgetHeap();
            Value mapped = mapOperation(call, receiver, arguments, flow);
            if (mapped != null) return mapped;
            // Unmodelled callees may mutate maps passed by reference. Never retain
            // write/read facts after a mutable container escapes to such a call.
            for (Value argument : arguments) if (!argument.objectId().isEmpty() && flow.maps.containsKey(argument.objectId())) flow.maps.get(argument.objectId()).escape();
            String owner = utilityOwner(call, receiver, flow);
            Value conversion = project.mappedConversion(currentType, owner, call, arguments);
            if (conversion != null) return conversion;
            var contractTypes=new ArrayList<String>();for(int i=0;i<arguments.size();i++){Value a=owner.equals("io.github.linpeilie.Converter")?project.selectionArgument(arguments.get(i),call.getArgument(i),currentType):arguments.get(i);contractTypes.add(a.type()==null?"":project.qualifyType(a.type().asString(),currentType));}
            var contract = project.contracts.method(owner, call.getNameAsString(), contractTypes, "");
            if(owner.equals("io.github.linpeilie.Converter")&&call.getNameAsString().equals("convert")&&project.converterOverrides()&&contract.kind()==FrameworkContracts.ReturnKind.NORMAL_NON_NULL)
                return new Value(SourceParsing.type("java.util.List<java.lang.Object>"),Nullness.MAYBE_NULL,ProjectContext.append(List.of(),path,call,"nullable-source","project Converter override prevents a default list return guarantee"),-1);
            if (project.externalContractsAllowed(owner) && contract.kind() != FrameworkContracts.ReturnKind.UNKNOWN) {
                String resultType = externalResultType(owner, call, receiver, arguments);
                Value result = project.contractValue(contract, arguments, resultType, currentType, call);
                if (result != null) return result;
            }
            Value result = project.invocation(currentMethod, currentType, receiver, call, arguments);
            invalidatePrivateCaches(flow);
            flow.locals.replaceAll((key,v)->v.objectId().startsWith("validated:")?new Value(v.type(),v.nullness(),v.trace(),v.parameter()):v);flow.validations.clear();
            flow.maps.forEach((id,state)->{if(id.startsWith("request-storage:"))state.escape();});
            if (result != UNKNOWN) return result;
        }
        return UNKNOWN;
    }
    private Value mapOperation(MethodCallExpr call, Value receiver, List<Value> arguments, Flow flow) {
        if (receiver.type() == null || !project.mapType(receiver.type().asString(), currentType)) return null;
        MapState state = flow.maps.get(receiver.objectId()); if (state == null) return null;
        String key = call.getArguments().isEmpty() ? null : stableKey(call.getArgument(0), flow);
        String method = call.getNameAsString();
        if(method.equals("computeIfAbsent")&&arguments.size()==2&&state.owned&&key!=null&&call.getArgument(1) instanceof LambdaExpr lambda){
            Value existing=state.entries.get(key);if(existing!=null&&existing.nullness()==Nullness.NON_NULL)return existing;
            Expression body=lambda.getExpressionBody().orElse(null);Value generated=UNKNOWN;
            if(body instanceof ObjectCreationExpr || body instanceof com.github.javaparser.ast.expr.StringLiteralExpr) generated=value(body,flow);
            if(generated.nullness()==Nullness.NON_NULL){invalidateAliasingKeys(state,key);state.entries.put(key,generated);state.present.add(key);project.proof(path,call,"core-owned-map-compute","same owned map/key and a proven non-null mapping expression; null or unknown callbacks retain nullable semantics");return generated;}
            if(body instanceof NullLiteralExpr)return new Value(SourceParsing.type(externalResultType("java.util.Map",call,receiver,arguments)),Nullness.MAYBE_NULL,ProjectContext.append(List.of(),path,call,"nullable-source","mapping callback can return null"),-1);
            state.escape();return null;
        }
        if (method.equals("put") && arguments.size() == 2) {
            if (state.entries.size() >= 256) { state.escape(); return UNKNOWN; }
            invalidateAliasingKeys(state,key);
            if (key == null) state.unknownKeys = true;
            else { state.entries.put(key, arguments.get(1)); state.present.add(key); if(key.startsWith("local:")) state.unknownKeys=true; }
            state.allNonNull &= arguments.get(1).nullness() == Nullness.NON_NULL;
            if (!arguments.get(1).objectId().isEmpty() && flow.maps.containsKey(arguments.get(1).objectId())) flow.maps.get(arguments.get(1).objectId()).escape();
            return UNKNOWN;
        }
        if (method.equals("get") && arguments.size() == 1) {
            Value stored = key == null ? null : state.entries.get(key);
            if (stored != null && state.owned) {
                if (stored.nullness() == Nullness.NON_NULL) project.proof(path, call, "core-owned-map-write-read", "same unmodified key was written with a non-null value; map has not escaped");
                return stored.typed(SourceParsing.type(externalResultType("java.util.Map",call,receiver,arguments)));
            }
            if (state.owned && state.allNonNull && key != null && state.present.contains(key)) {
                project.proof(path, call, "core-owned-map-present-nonnull", "key is present and every value written to the owned map is non-null");
                return new Value(SourceParsing.type(externalResultType("java.util.Map",call,receiver,arguments)), Nullness.NON_NULL);
            }
            if (state.owned && !state.unknownKeys && key != null && !state.present.contains(key))
                return new Value(SourceParsing.type(externalResultType("java.util.Map",call,receiver,arguments)), Nullness.NULL,
                    ProjectContext.append(List.of(),path,call,"nullable-source","absent key in an owned map"),-1);
            return null;
        }
        if (method.equals("remove")) {
            invalidateAliasingKeys(state,key);
            if (key == null || key.startsWith("local:")) state.unknownKeys=true;
            if (key != null) { state.entries.remove(key); state.present.remove(key); }
            return UNKNOWN;
        }
        if (method.equals("clear")) { state.entries.clear(); state.present.clear(); state.unknownKeys=false; return UNKNOWN; }
        if (!Set.of("containsKey","containsValue","size","isEmpty").contains(method)) state.escape();
        return null;
    }
    private static void invalidatePrivateCaches(Flow flow){flow.maps.forEach((id,state)->{if(id.startsWith("private-cache:")){state.entries.clear();state.present.clear();state.unknownKeys=true;state.allNonNull=false;}});}
    private static void invalidateAliasingKeys(MapState state,String key) {
        if (key == null || key.startsWith("local:")) { state.entries.clear(); state.present.clear(); }
        else { state.entries.keySet().removeIf(k -> k.startsWith("local:")); state.present.removeIf(k -> k.startsWith("local:")); }
    }
    private String stableKey(Expression expression, Flow flow) {
        Expression key = unwrap(expression);
        if (key instanceof NameExpr name && flow.locals.containsKey(name.getNameAsString())) {
            Value value=flow.locals.get(name.getNameAsString());
            if (value.type()==null) return null;
            String type=project.qualify(value.type().asString(),currentType);
            var declared=project.types.get(type);
            if (!value.type().isPrimitiveType() && !(declared!=null && declared.isEnum)
                && !Set.of("java.lang.String","java.lang.Class","java.lang.Boolean","java.lang.Byte","java.lang.Short","java.lang.Character","java.lang.Integer","java.lang.Long","java.lang.Float","java.lang.Double").contains(type)) return null;
            return "local:"+name.getNameAsString()+":"+flow.generations.getOrDefault(name.getNameAsString(),0);
        }
        if (key instanceof com.github.javaparser.ast.expr.StringLiteralExpr literal) return "literal:string:"+literal.asString();
        if (key instanceof com.github.javaparser.ast.expr.IntegerLiteralExpr literal) return "literal:int:"+literal.asNumber();
        if (key instanceof com.github.javaparser.ast.expr.LongLiteralExpr literal) return "literal:long:"+literal.asNumber();
        if (key instanceof com.github.javaparser.ast.expr.CharLiteralExpr literal) return "literal:char:"+literal.asChar();
        if (key instanceof BooleanLiteralExpr literal) return "literal:boolean:"+literal.getValue();
        if (key instanceof NullLiteralExpr) return "literal:null";
        if (key instanceof ClassExpr literal) return "literal:class:"+project.qualifyType(literal.getType().asString(),currentType);
        return null;
    }
    private String utilityOwner(MethodCallExpr call, Value receiver, Flow flow) {
        if (receiver.type() != null) return project.qualify(receiver.type().asString(), currentType);
        if (call.getScope().isPresent()) {
            String named = call.getScope().get().toString();
            if (flow.locals.containsKey(named) || project.field(currentType, named) != null) return "";
            return project.qualify(named, currentType);
        }
        if (currentType.methods.stream().anyMatch(m -> m.name.equals(call.getNameAsString()))) return "";
        var imports = unit.getImports().stream().filter(i -> i.isStatic() && !i.isAsterisk() && i.getName().getIdentifier().equals(call.getNameAsString())).toList();
        return imports.size() == 1 ? imports.getFirst().getNameAsString().substring(0, imports.getFirst().getNameAsString().lastIndexOf('.')) : "";
    }
    private String externalResultType(String owner, MethodCallExpr call, Value receiver, List<Value> arguments) {
        if (owner.equals("io.github.linpeilie.Converter") && arguments.size() == 2 && arguments.get(1).type() != null) {
            var target = arguments.get(1).type();
            String element = target.isClassOrInterfaceType() ? target.asClassOrInterfaceType().getTypeArguments().filter(a -> a.size() == 1).map(a -> a.get(0).asString()).orElse("java.lang.Object") : "java.lang.Object";
            return arguments.get(0).type() != null && arguments.get(0).type().asString().contains("List") ? "java.util.List<"+element+">" : element;
        }
        String method = call.getNameAsString();
        if (method.equals("get") && receiver.type() != null && receiver.type().isClassOrInterfaceType() && project.mapType(owner,currentType)) return receiver.type().asClassOrInterfaceType().getTypeArguments()
            .filter(a -> a.size() == 2).map(a -> a.get(1).asString()).orElse("java.lang.Object");
        if (method.toLowerCase(java.util.Locale.ROOT).contains("list") || owner.equals("java.util.List")) return "java.util.List";
        if (method.toLowerCase(java.util.Locale.ROOT).contains("map") || owner.equals("java.util.Map")) return "java.util.Map";
        if (method.toLowerCase(java.util.Locale.ROOT).contains("set") || owner.equals("java.util.Set")) return "java.util.Set";
        if (method.equals("stream") || method.equals("parallelStream")) return "java.util.stream.Stream";
        return "java.lang.Object";
    }

    private boolean trustedUtility(MethodCallExpr call, Set<String> types, Flow flow) {
        if (call.getScope().isEmpty()) return false;
        Expression scope = call.getScope().get();
        if (scope.isNameExpr() && (flow.locals.containsKey(scope.toString()) || currentType != null && project.field(currentType, scope.toString()) != null)) return false;
        if (currentType == null) return false;
        String qualified=project.qualify(scope.toString(),currentType);
        return project.externalContractsAllowed(qualified) && types.contains(qualified);
    }

    private Value localOrField(String name, Flow flow) {
        Value local = flow.locals.get(name);
        if (local != null) return local;
        if (project != null && currentType != null) {
            Value assigned = flow.locals.get("this." + name);
            if (assigned != null) return assigned;
            var field = project.field(currentType, name);
            if (field != null) return new Value(SourceParsing.type(project.qualifyType(field.type(), currentType)), field.state());
        }
        return UNKNOWN;
    }

    private boolean isObjectsCall(MethodCallExpr call, Flow flow) {
        Expression scope = call.getScope().orElse(null);
        if (scope == null) return false;
        String root = scope.isNameExpr() ? scope.asNameExpr().getNameAsString() : "java";
        // An expression name can shadow a type name in a method call.
        if (flow.locals.containsKey(root) || types.stream().anyMatch(type -> type.getFieldByName(root).isPresent())) {
            return false;
        }
        return scope.isNameExpr() ? isJdkType(root, "java.util.Objects")
            : scope.isFieldAccessExpr() && scope.toString().equals("java.util.Objects");
    }

    private Value access(Expression access, Expression scope, Expression assigned, Flow flow) {
        Value receiver = value(scope, flow);
        if (access instanceof ArrayAccessExpr array) value(array.getIndex(), flow);
        Value result = assigned == null ? UNKNOWN : value(assigned, flow);
        if (assigned != null) { escape(result,flow); flow.invalidate(access.toString());flow.validations.clear();flow.locals.replaceAll((key,v)->v.objectId().startsWith("validated:")?new Value(v.type(),v.nullness(),v.trace(),v.parameter()):v); }
        if (access instanceof ArrayAccessExpr) {
            dereference(access, scope, receiver, flow, Sink.ARRAY);
        } else if (access instanceof FieldAccessExpr field && receiver.nullness() != Nullness.NON_NULL
            && isInstanceField(receiver.type(), field)) {
            dereference(access, scope, receiver, flow, receiver.type().isArrayType() ? Sink.ARRAY_LENGTH : Sink.FIELD);
        }
        if (project != null && access instanceof FieldAccessExpr field) {
            String key = field.toString();
            if(assigned==null&&currentType!=null&&!flow.locals.containsKey(field.getScope().toString())&&project.qualify(field.getScope().toString(),currentType).equals(currentType.name)){
                Value cache=flow.locals.get(field.getNameAsString());if(cache!=null&&cache.objectId().startsWith("private-cache:"))return cache;
            }
            if (assigned == null && flow.locals.containsKey(key)) return flow.locals.get(key);
            var type = scope.isThisExpr() || scope.isSuperExpr() ? currentType
                : receiver.type() == null ? null : project.types.get(project.qualify(receiver.type().asString(), currentType));
            var declared = project.field(type, field.getNameAsString());
            if (assigned != null) {
                Value updated = declared == null ? result : new Value(SourceParsing.type(project.qualifyType(declared.type(), type)), result.nullness(), result.trace(), result.parameter());
                flow.locals.put(key, updated); return updated;
            }
            if (declared != null) {
                Value constrained=project.validation.property(receiver,field.getNameAsString(),path,field);
                if(constrained!=null)return constrained;
                return new Value(SourceParsing.type(project.qualifyType(declared.type(), type)), declared.state());
            }
        }
        return result;
    }

    private Branch condition(Expression expression, Flow input) {
        Expression test = unwrap(expression);
        if (test instanceof UnaryExpr unary && unary.getOperator() == UnaryExpr.Operator.LOGICAL_COMPLEMENT) {
            Branch inner = condition(unary.getExpression(), input);
            return new Branch(inner.no(), inner.yes());
        }
        if (test instanceof BinaryExpr binary) {
            if (binary.getOperator() == BinaryExpr.Operator.AND) {
                Branch left = condition(binary.getLeft(), input);
                Branch right = condition(binary.getRight(), left.yes());
                return new Branch(right.yes(), Flow.merge(left.no(), right.no()));
            }
            if (binary.getOperator() == BinaryExpr.Operator.OR) {
                Branch left = condition(binary.getLeft(), input);
                Branch right = condition(binary.getRight(), left.no());
                return new Branch(Flow.merge(left.yes(), right.yes()), right.no());
            }
        }
        Flow yes = input.copy();
        Value tested = value(test, yes);
        unbox(test, test, tested, yes);
        Flow no = yes.copy();
        if (test instanceof NameExpr named && input.locals.containsKey(named.getNameAsString())) {
            String name = named.getNameAsString();
            Boolean known = input.assumptions.getOrDefault(name, tested.booleanValue());
            yes.assumptions.put(name, true); no.assumptions.put(name, false);
            if (known != null) (known ? no : yes).reachable = false;
            if (yes.reachable && yes.restore(name, true) && project != null) project.proof(path, test, "core-repeated-local-boolean", "same unchanged local boolean is true");
            if (no.reachable && no.restore(name, false) && project != null) project.proof(path, test, "core-repeated-local-boolean", "same unchanged local boolean is false");
        } else if (test instanceof BooleanLiteralExpr literal) {
            (literal.getValue() ? no : yes).reachable = false;
        } else if (test instanceof BinaryExpr comparison
            && (comparison.getOperator() == BinaryExpr.Operator.EQUALS || comparison.getOperator() == BinaryExpr.Operator.NOT_EQUALS)) {
            Expression left = unwrap(comparison.getLeft());
            Expression right = unwrap(comparison.getRight());
            Expression checked = left.isNullLiteralExpr() ? right : right.isNullLiteralExpr() ? left : null;
            boolean equality = comparison.getOperator() == BinaryExpr.Operator.EQUALS;
            constrain(checked, Nullness.NULL, equality ? yes : no);
            constrain(checked, Nullness.NON_NULL, equality ? no : yes);
        } else if (test instanceof InstanceOfExpr instance) {
            constrain(unwrap(instance.getExpression()), Nullness.NON_NULL, yes);
        } else if (test instanceof MethodCallExpr call && call.getArguments().size() == 1
            && (call.getNameAsString().equals("isNull") || call.getNameAsString().equals("nonNull"))
            && isObjectsCall(call, yes)) {
            Expression checked = unwrap(call.getArgument(0));
            boolean isNull = call.getNameAsString().equals("isNull");
            constrain(checked, Nullness.NULL, isNull ? yes : no);
            constrain(checked, Nullness.NON_NULL, isNull ? no : yes);
        } else if (project != null && test instanceof MethodCallExpr call && call.getArguments().size() == 1
            && Set.of("isNull", "isNotNull").contains(call.getNameAsString())
            && trustedUtility(call, Set.of("cn.hutool.core.util.ObjectUtil", "cn.hutool.core.util.ObjUtil"), yes)) {
            Expression checked = unwrap(call.getArgument(0)); boolean isNull = call.getNameAsString().equals("isNull");
            constrain(checked, Nullness.NON_NULL, isNull ? no : yes);
            if (localOrField(checked.toString(),input).nullness()==Nullness.NULL) (isNull ? no : yes).reachable=false;
        }
        if (project != null && test instanceof MethodCallExpr call && call.getArguments().size() == 1) {
            Value receiver = call.getScope().map(s -> localOrField(s.toString(), input)).orElse(UNKNOWN);
            String owner = utilityOwner(call, receiver, input);
            var predicate = project.externalContractsAllowed(owner) ? project.contracts.predicate(owner, call.getNameAsString(), 1) : FrameworkContracts.PredicateKind.NONE;
            Expression checked = unwrap(call.getArgument(0));
            // Hutool's ObjectUtil also calls equals(null). Keep that case open
            // for arbitrary objects, but JDK value/collection contracts require
            // equals(null) to be false. This prevents a known non-null list from
            // gaining a fictitious null-return branch in a conversion helper.
            Value checkedValue = localOrField(checked.toString(), input);
            if (predicate != FrameworkContracts.PredicateKind.NONE
                && Set.of("cn.hutool.core.util.ObjectUtil", "cn.hutool.core.util.ObjUtil").contains(owner)
                && Set.of("isNull", "isNotNull").contains(call.getNameAsString())
                && checkedValue.type() != null && jdkNullEquality(checkedValue.type())) {
                predicate = call.getNameAsString().equals("isNull") ? FrameworkContracts.PredicateKind.NULL : FrameworkContracts.PredicateKind.NOT_NULL;
                if (checkedValue.nullness() == Nullness.NON_NULL) project.proof(path, test, "jdk21-value-null-equality",
                    "JDK value or container equality excludes null for a known non-null argument");
            }
            switch (predicate) {
                case NULL -> { constrain(checked, Nullness.NULL, yes); constrain(checked, Nullness.NON_NULL, no); }
                case NOT_NULL -> { constrain(checked, Nullness.NON_NULL, yes); constrain(checked, Nullness.NULL, no); }
                case EMPTY -> {
                    if (localOrField(checked.toString(), input).nullness() == Nullness.NULL) no.reachable = false;
                    constrain(checked, Nullness.NON_NULL, no);
                    if (no.reachable) project.proof(path, test, owner+"."+call.getNameAsString(), "empty predicate is false, therefore the argument is non-null");
                }
                case NOT_EMPTY -> {
                    if (localOrField(checked.toString(), input).nullness() == Nullness.NULL) yes.reachable = false;
                    constrain(checked, Nullness.NON_NULL, yes);
                    if (yes.reachable) project.proof(path, test, owner+"."+call.getNameAsString(), "non-empty predicate is true, therefore the argument is non-null");
                }
                default -> { }
            }
            if (call.getNameAsString().equals("containsKey") && call.getScope().isPresent()) {
                Value map = localOrField(call.getScope().get().toString(), input);
                String key = stableKey(call.getArgument(0), input);
                if (key != null && input.maps.containsKey(map.objectId())) {
                    var state = input.maps.get(map.objectId());
                    yes.maps.get(map.objectId()).present.add(key); no.maps.get(map.objectId()).present.remove(key);
                    no.maps.get(map.objectId()).entries.remove(key);
                    if (state.owned && state.present.contains(key)) no.reachable = false;
                    if (state.owned && !state.unknownKeys && !state.present.contains(key)) yes.reachable = false;
                }
            }
        }
        if(project!=null&&test instanceof MethodCallExpr call&&call.getNameAsString().equals("isEmpty")&&call.getArguments().isEmpty()&&call.getScope().isPresent()){
            Value set=localOrField(call.getScope().get().toString(),input);var validation=input.validations.get(set.objectId());
            if(validation!=null&&validation.generation==input.generations.getOrDefault(validation.object,0)){
                Value object=yes.locals.get(validation.object);if(object!=null)yes.locals.put(validation.object,project.validation.validated(object.typed(SourceParsing.type(project.qualifyType(object.type().asString(),currentType))),validation.groups));
            }
        }
        return new Branch(yes, no);
    }

    private boolean jdkNullEquality(Type type) {
        if (type.isArrayType() || type.isPrimitiveType()) return true;
        String name = project.qualify(type.asString(), currentType);
        if(name.startsWith("java.util.")&&project.nonstandardCollectionEquality(name))return false;
        return project.externalContractsAllowed(name) && Set.of("java.lang.String", "java.lang.Class", "java.lang.Boolean", "java.lang.Byte", "java.lang.Short", "java.lang.Character",
            "java.lang.Integer", "java.lang.Long", "java.lang.Float", "java.lang.Double", "java.util.Collection", "java.util.List", "java.util.Set",
            "java.util.Map", "java.util.ArrayList", "java.util.LinkedList", "java.util.HashSet", "java.util.LinkedHashSet", "java.util.TreeSet",
            "java.util.HashMap", "java.util.LinkedHashMap", "java.util.TreeMap", "java.util.concurrent.ConcurrentHashMap").contains(name);
    }

    private void unbox(Node site, Expression expression, Value operand, Flow flow) {
        if (operand.type() == null || !operand.type().isClassOrInterfaceType()) return;
        String type = operand.type().asClassOrInterfaceType().getNameWithScope();
        if (Set.of("Boolean", "Byte", "Short", "Character", "Integer", "Long", "Float", "Double").stream()
            .anyMatch(name -> type.equals(name) || type.equals("java.lang." + name))) {
            captureExceptions(flow); dereference(site, expression, operand, flow, Sink.UNBOX);
        }
    }
    private void captureExceptions(Flow flow) {
        if (exceptionFrames.isEmpty()) return;
        Flow possible = flow.copy(); possible.reachable = true;
        for (ExceptionFrame frame : exceptionFrames) frame.state = mergeReachable(frame.state, possible);
    }

    private void dereference(Node site, Expression scope, Value receiver, Flow flow, Sink sink) {
        if (!flow.reachable) return;
        if (receiver.nullness() == Nullness.NULL || receiver.nullness() == Nullness.MAYBE_NULL) {
            String name = unwrap(scope) instanceof NameExpr local ? " " + local.getNameAsString() : "";
            String message = sink.description + (receiver.nullness() == Nullness.NULL
                ? name + " 在此路径上为 null。" : name + " 在某条分析路径上可能为 null。");
            String member = switch (sink) {
                case METHOD -> ((MethodCallExpr) site).getNameAsString();
                case FIELD -> ((FieldAccessExpr) site).getNameAsString();
                case METHOD_REFERENCE -> ((com.github.javaparser.ast.expr.MethodReferenceExpr) site).getIdentifier();
                default -> "";
            };
            boolean unique = site.getBegin().map(position ->
                position.line < dereferencesByLine.length && dereferencesByLine[position.line] == 1).orElse(false);
            emit.accept(new Dereference(site, message, sink.kind, member, unique,
                ProjectContext.append(receiver.trace(), path, site, "sink", message),
                receiver.nullness() == Nullness.NULL ? "definite" : "possible"));
        }
        if (receiver.nullness() == Nullness.NULL) flow.reachable = false;
        refine(scope, receiver, Nullness.NON_NULL, flow);
    }

    private static void constrain(Expression expression, Nullness wanted, Flow flow) {
        if (expression instanceof NameExpr name) {
            Value previous = flow.locals.get(name.getNameAsString());
            if (previous == null) return;
            if ((previous.nullness() == Nullness.NULL || previous.nullness() == Nullness.NON_NULL)
                && previous.nullness() != wanted) {
                flow.reachable = false;
            }
            refine(expression, previous, wanted, flow);
        }
    }

    private static void refine(Expression expression, Value previous, Nullness wanted, Flow flow) {
        if (flow.reachable && unwrap(expression) instanceof NameExpr name
            && flow.locals.get(name.getNameAsString()) == previous) {
            flow.locals.put(name.getNameAsString(), previous.state(wanted));
        }
    }

    private boolean isInstanceMethod(Type type, MethodCallExpr call) {
        if (type == null) return false;
        if (project != null && currentType != null) {
            String key = currentType.name + ":" + type.asString() + "#" + call.getNameAsString() + "/" + call.getArguments().size();
            Boolean cached = project.instanceMethodFacts.get(key);
            if (cached != null) return cached;
            boolean result = instanceMethodUncached(type, call);
            if (project.instanceMethodFacts.size() < 100_000) project.instanceMethodFacts.put(key, result);
            return result;
        }
        return instanceMethodUncached(type, call);
    }
    private boolean instanceMethodUncached(Type type, MethodCallExpr call) {
        if (project != null && currentType != null) {
            if (project.mapType(type.asString(), currentType) && isJdkInstanceMethod("java.util.Map", call.getNameAsString(), call.getArguments().size())) return true;
            List<Value> args = call.getArguments().stream().map(ignored -> UNKNOWN).toList();
            var candidates = project.targets(currentType, type.asString(), call, args);
            if (!candidates.isEmpty()) return candidates.stream().noneMatch(m -> m.isStatic);
            if (project.inherits(type.asString(), "com.baomidou.mybatisplus.core.mapper.BaseMapper", currentType)
                && Set.of("selectById", "selectOne").contains(call.getNameAsString())) return true;
        }
        String method = call.getNameAsString();
        int arity = call.getArguments().size();
        boolean objectMethod = isJdkInstanceMethod("java.lang.Object", method, arity);
        if (type.isArrayType()) return (method.equals("clone") && arity == 0) || objectMethod;
        if (!type.isClassOrInterfaceType()) return false;
        String name = type.asClassOrInterfaceType().getNameWithScope();
        ClassOrInterfaceDeclaration declaration = localType(name, call);
        if (declaration != null) {
            if (!declaration.getExtendedTypes().isEmpty() || !declaration.getImplementedTypes().isEmpty()) return false;
            var candidates = declaration.getMethodsByName(method).stream().filter(candidate -> {
                int parameters = candidate.getParameters().size();
                return parameters == arity || parameters > 0 && candidate.getParameter(parameters - 1).isVarArgs()
                    && arity >= parameters - 1;
            }).toList();
            return candidates.isEmpty() ? objectMethod : candidates.stream().noneMatch(MethodDeclaration::isStatic);
        }
        return JDK_METHODS.keySet().stream().anyMatch(qualified ->
            isJdkInstanceMethod(qualified, method, arity) && isJdkType(name, qualified));
    }

    private static boolean isJdkInstanceMethod(String type, String method, int arity) {
        var candidates = JDK_METHODS.get(type).getOrDefault(method, List.of()).stream()
            .filter(candidate -> candidate.accepts(arity)).toList();
        return !candidates.isEmpty() && candidates.stream().noneMatch(MethodKind::isStatic);
    }

    private boolean isInstanceField(Type type, FieldAccessExpr access) {
        if (type == null) return false;
        String field = access.getNameAsString();
        if (type.isArrayType()) return field.equals("length");
        if (!type.isClassOrInterfaceType()) return false;
        if (project != null && currentType != null) {
            var member = project.field(project.types.get(project.qualify(type.asString(), currentType)), field);
            return member != null && !member.isStatic();
        }
        ClassOrInterfaceDeclaration declaration = localType(type.asClassOrInterfaceType().getNameWithScope(), access);
        return declaration != null && !declaration.isInterface()
            && declaration.getFieldByName(field).filter(member -> !member.isStatic()).isPresent();
    }

    private ClassOrInterfaceDeclaration localType(String name, Node use) {
        if (typeParameters.stream().anyMatch(parameter -> parameter.getNameAsString().equals(name))
            || unit.getImports().stream().anyMatch(imported -> !imported.isAsterisk()
                && imported.getName().getIdentifier().equals(name))) return null;
        var matches = types.stream().filter(type -> type.getNameAsString().equals(name)).toList();
        if (matches.size() == 1 && matches.getFirst() instanceof ClassOrInterfaceDeclaration declaration) {
            Node parent = declaration.getParentNode().orElse(null);
            if (parent == unit || parent instanceof TypeDeclaration<?> && parent.isAncestorOf(use)) return declaration;
        }
        return null;
    }

    private boolean isJdkType(String name, String qualified) {
        if (name.equals(qualified)) return true;
        if (!qualified.endsWith("." + name) || name.contains(".")
            || types.stream().anyMatch(type -> type.getNameAsString().equals(name))
            || typeParameters.stream().anyMatch(parameter -> parameter.getNameAsString().equals(name))) return false;
        var explicit = unit.getImports().stream()
            .filter(imported -> !imported.isAsterisk() && imported.getName().getIdentifier().equals(name)).toList();
        if (!explicit.isEmpty()) return explicit.size() == 1 && explicit.getFirst().getNameAsString().equals(qualified);
        // These packages do not collide for the built-in type names above.
        var onDemand = unit.getImports().stream().filter(imported -> imported.isAsterisk()).toList();
        if (onDemand.stream().anyMatch(imported -> imported.isStatic()
            || !SUPPORTED_ON_DEMAND_IMPORTS.contains(imported.getNameAsString()))) return false;
        return qualified.startsWith("java.lang.") || onDemand.stream()
            .anyMatch(imported -> qualified.equals(imported.getNameAsString() + "." + name));
    }

    private static Expression unwrap(Expression expression) {
        while (expression instanceof EnclosedExpr enclosed) expression = enclosed.getInner();
        return expression;
    }

    static Nullness join(Nullness left, Nullness right) {
        if (left == right) return left;
        return left == Nullness.NULL || left == Nullness.MAYBE_NULL
            || right == Nullness.NULL || right == Nullness.MAYBE_NULL ? Nullness.MAYBE_NULL : Nullness.UNKNOWN;
    }

    static Value mergeValue(Value left, Value right) {
        Nullness state = join(left.nullness(), right.nullness());
        var trace = left.nullness() == Nullness.NULL || left.nullness() == Nullness.MAYBE_NULL ? left.trace() : right.trace();
        return new Value(Objects.equals(left.type(), right.type()) ? left.type() : left.type() != null ? left.type() : right.type(), state,
            trace, left.parameter() == right.parameter() ? left.parameter() : -1,
            left.objectId().equals(right.objectId()) ? left.objectId() : "", Objects.equals(left.booleanValue(),right.booleanValue()) ? left.booleanValue() : null);
    }

    private record ValidationState(String object,int generation,Set<String> groups) {}
    private static final class Flow {
        private final Map<String,ValidationState> validations=new HashMap<>();
        private final Map<String, Value> locals = new HashMap<>();
        private boolean reachable = true;
        private final Map<String,Boolean> assumptions = new HashMap<>();
        private final Map<String,Map<String,Value>> branches = new HashMap<>();
        private final Map<String,MapState> maps = new HashMap<>();
        private final Map<String,Integer> generations = new HashMap<>();
        private void invalidate(String variable) {
            validations.values().removeIf(v->v.object.equals(variable));
            assumptions.remove(variable); branches.remove(variable+"=true"); branches.remove(variable+"=false");
            branches.values().forEach(values -> values.remove(variable));
            locals.keySet().removeIf(key -> key.startsWith(variable+".") || key.startsWith(variable+"["));
            branches.values().forEach(values -> values.keySet().removeIf(key -> key.startsWith(variable+".") || key.startsWith(variable+"[")));
            generations.merge(variable,1,Integer::sum);
        }
        private void remember(String variable, boolean state, Flow branch) {
            if (!branch.reachable || branches.size() >= 32) return;
            var values = new HashMap<String,Value>();
            for (String local : locals.keySet()) if (!local.contains(".") && !local.contains("[") && !local.equals(variable) && branch.locals.containsKey(local)) values.put(local, branch.locals.get(local));
            branches.put(variable+"="+state, values);
        }
        private boolean restore(String variable, boolean state) {
            var values = branches.get(variable+"="+state); boolean proof = false;
            if (values != null) for (var entry : values.entrySet()) {
                Value previous = locals.get(entry.getKey());
                if (previous != null) { if (previous.nullness() != Nullness.NON_NULL && entry.getValue().nullness() == Nullness.NON_NULL) proof = true; locals.put(entry.getKey(), entry.getValue()); }
            }
            return proof;
        }
        private void forgetHeap() { locals.keySet().removeIf(key -> key.contains(".") || key.contains("[")); }

        private Flow copy() {
            var copy = new Flow();
            copy.replaceWith(this);
            return copy;
        }

        private void replaceWith(Flow other) {
            validations.clear();validations.putAll(other.validations);
            locals.clear();
            locals.putAll(other.locals);
            reachable = other.reachable;
            assumptions.clear(); assumptions.putAll(other.assumptions);
            branches.clear(); other.branches.forEach((key,value) -> branches.put(key,new HashMap<>(value)));
            maps.clear(); other.maps.forEach((key,value) -> maps.put(key,value.copy()));
            generations.clear(); generations.putAll(other.generations);
        }

        private void forgetValues() {
            validations.clear();
            locals.replaceAll((name, value) -> new Value(value.type(), Nullness.UNKNOWN));
            assumptions.clear(); branches.clear();
            maps.values().forEach(MapState::escape);
        }

        private static Flow merge(Flow left, Flow right) {
            if (!left.reachable) return right;
            if (!right.reachable) return left;
            Flow result = left.copy();
            result.validations.entrySet().removeIf(v->!Objects.equals(right.validations.get(v.getKey()),v.getValue()));
            result.locals.replaceAll((name, value) -> {
                Value other = right.locals.getOrDefault(name, UNKNOWN);
                return value == other ? value : mergeValue(value, other);
            });
            result.assumptions.entrySet().removeIf(e -> !Objects.equals(e.getValue(),right.assumptions.get(e.getKey())));
            result.branches.entrySet().removeIf(e -> !Objects.equals(e.getValue(),right.branches.get(e.getKey())));
            result.maps.entrySet().removeIf(e -> !right.maps.containsKey(e.getKey()));
            result.maps.forEach((id,state) -> {
                var other=right.maps.get(id); state.owned &= other.owned; state.allNonNull &= other.allNonNull; state.unknownKeys |= other.unknownKeys;
                state.present.retainAll(other.present);
                state.entries.entrySet().removeIf(e -> !other.entries.containsKey(e.getKey()));
                state.entries.replaceAll((key,value) -> mergeValue(value,other.entries.get(key)));
            });
            right.generations.forEach((name,generation) -> result.generations.merge(name,generation,Math::max));
            return result;
        }
    }
}
