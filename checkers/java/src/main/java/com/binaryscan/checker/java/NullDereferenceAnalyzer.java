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

    record Value(Type type, Nullness nullness, List<Map<String,Object>> trace, int parameter) {
        Value(Type type, Nullness nullness) { this(type, nullness, List.of(), -1); }
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
    private ProjectContext.TypeInfo currentType;
    private final Map<ProjectContext.MethodInfo, Value> returns = new HashMap<>();
    private final Deque<List<Value>> yields = new ArrayDeque<>();
    private static final class ControlFrame {
        Flow breaks, continues;
    }
    private static final class ExceptionFrame { Flow state; }
    private final Deque<ControlFrame> breakFrames = new ArrayDeque<>();
    private final Deque<ControlFrame> loopFrames = new ArrayDeque<>();
    private final Deque<ExceptionFrame> exceptionFrames = new ArrayDeque<>();

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
        Flow flow = new Flow();
        for (int index = 0; index < callable.getParameters().size(); index++) {
            var parameter = callable.getParameter(index);
            Value input = currentMethod == null ? UNKNOWN : currentMethod.inputs[index];
            if (project != null && input.nullness() == Nullness.UNKNOWN && project.nullableAnnotations(parameter.getAnnotations(), currentType))
                input = new Value(parameter.getType(), Nullness.MAYBE_NULL,
                    ProjectContext.append(List.of(), path, parameter, "nullable-source", "nullable parameter contract"), index);
            flow.locals.put(parameter.getNameAsString(), new Value(parameter.isVarArgs() ? new ArrayType(parameter.getType().clone())
                : parameter.getType(), input.nullness(), input.trace(), index));
        }
        statement(body, flow);
        if (project != null) project.finish(currentMethod, returns.get(currentMethod));
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
                flow.replaceWith(Flow.merge(branch.yes(), branch.no()));
            }
            case ReturnStmt returned -> {
                returned.getExpression().ifPresent(expression -> {
                    Value result = value(expression, flow);
                    if (currentMethod != null && SourceParsing.type(currentMethod.result).isPrimitiveType()) unbox(returned, expression, result, flow);
                    if (project != null) project.returned(currentMethod, result, returned, returns);
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
                constructor.getArguments().forEach(e -> value(e, flow));
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
            .allMatch(e -> e.getValue().nullness() == right.locals.get(e.getKey()).nullness());
    }
    private void tryStatement(com.github.javaparser.ast.stmt.TryStmt tried, Flow flow) {
        Value priorReturns = returns.get(currentMethod);
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
                if (priorReturns == null) returns.remove(currentMethod); else returns.put(currentMethod, priorReturns);
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
                yield new Value(cast.getType(), cast.getType().isPrimitiveType() ? Nullness.UNKNOWN : operand.nullness(), operand.trace(), operand.parameter());
            }
            case VariableDeclarationExpr declaration -> {
                declaration.getVariables().forEach(variable -> {
                    Value initial = variable.getInitializer().map(expr -> value(expr, flow)).orElse(UNKNOWN);
                    Type type = variable.getType().isVarType() ? initial.type() : variable.getType();
                    if (type != null && type.isPrimitiveType()) variable.getInitializer().ifPresent(initializer -> unbox(variable, initializer, initial, flow));
                    flow.locals.put(variable.getNameAsString(), new Value(type, initial.nullness(), initial.trace(), initial.parameter()));
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
                yield UNKNOWN;
            }
            case InstanceOfExpr test -> {
                value(test.getExpression(), flow);
                yield UNKNOWN;
            }
            case ObjectCreationExpr creation -> {
                creation.getScope().ifPresent(scope -> value(scope, flow));
                creation.getArguments().forEach(argument -> value(argument, flow));
                yield new Value(creation.getType(), Nullness.NON_NULL);
            }
            case ArrayCreationExpr array -> {
                array.getLevels().forEach(level -> level.getDimension().ifPresent(dimension -> value(dimension, flow)));
                array.getInitializer().ifPresent(initializer -> value(initializer, flow));
                yield new Value(array.createdType(), Nullness.NON_NULL);
            }
            case ArrayInitializerExpr initializer -> {
                initializer.getValues().forEach(element -> value(element, flow));
                yield new Value(null, Nullness.NON_NULL);
            }
            case com.github.javaparser.ast.expr.StringLiteralExpr ignored -> new Value(SourceParsing.type("java.lang.String"), Nullness.NON_NULL);
            case com.github.javaparser.ast.expr.IntegerLiteralExpr ignored -> new Value(SourceParsing.type("int"), Nullness.NON_NULL);
            case LiteralExpr ignored -> new Value(null, Nullness.NON_NULL);
            case ThisExpr ignored -> new Value(null, Nullness.NON_NULL);
            case SuperExpr ignored -> new Value(null, Nullness.NON_NULL);
            case LambdaExpr lambda -> {
                Flow closure = flow.copy();
                lambda.getParameters().forEach(p -> closure.locals.put(p.getNameAsString(), new Value(p.getType(), Nullness.UNKNOWN)));
                var enclosing = currentMethod; currentMethod = null;
                statement(lambda.getBody(), closure); currentMethod = enclosing;
                yield new Value(null, Nullness.NON_NULL);
            }
            case com.github.javaparser.ast.expr.MethodReferenceExpr reference -> {
                if (!reference.getScope().isTypeExpr()) {
                    Value receiver = value(reference.getScope(), flow);
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
            case ClassExpr ignored -> new Value(null, Nullness.NON_NULL);
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
                Value updated = new Value(previous.type(), simple ? assigned.nullness() : Nullness.UNKNOWN, assigned.trace(), assigned.parameter());
                flow.locals.put(name.getNameAsString(), updated);
                return updated;
            }
            if (project != null && currentType != null) {
                var field = project.field(currentType, name.getNameAsString());
                if (field != null) {
                    Value updated = new Value(SourceParsing.type(project.qualifyType(field.type(), currentType)), assigned.nullness(), assigned.trace(), assigned.parameter());
                    flow.locals.put("this." + name.getNameAsString(), updated); return updated;
                }
            }
        }
        return UNKNOWN;
    }

    private Value call(MethodCallExpr call, Flow flow) {
        Expression scope = call.getScope().orElse(null);
        Value receiver = scope == null ? UNKNOWN : value(scope, flow);
        List<Value> arguments = call.getArguments().stream().map(argument -> value(argument, flow)).toList();
        captureExceptions(flow);
        if (receiver.nullness() != Nullness.NON_NULL && isInstanceMethod(receiver.type(), call)) {
            dereference(call, scope, receiver, flow, Sink.METHOD);
        }
        if (call.getNameAsString().equals("requireNonNull") && (arguments.size() == 1 || arguments.size() == 2)
            && isObjectsCall(call, flow)) {
            Value checked = arguments.getFirst();
            if (checked.nullness() == Nullness.NULL) flow.reachable = false;
            refine(call.getArgument(0), checked, Nullness.NON_NULL, flow);
            return new Value(checked.type(), Nullness.NON_NULL);
        }
        if (project != null && !arguments.isEmpty() && Set.of("notNull", "checkNotNull").contains(call.getNameAsString())
            && trustedUtility(call, Set.of("org.springframework.util.Assert", "cn.hutool.core.lang.Assert", "com.google.common.base.Preconditions"), flow)) {
            Value checked = arguments.getFirst();
            if (checked.nullness() == Nullness.NULL) flow.reachable = false;
            refine(call.getArgument(0), checked, Nullness.NON_NULL, flow);
            return new Value(checked.type(), Nullness.NON_NULL, checked.trace(), checked.parameter());
        }
        if (project != null && currentType != null) {
            Value result = project.invocation(currentMethod, currentType, receiver, call, arguments);
            if (result != UNKNOWN) return result;
        }
        return UNKNOWN;
    }

    private boolean trustedUtility(MethodCallExpr call, Set<String> types, Flow flow) {
        if (call.getScope().isEmpty()) return false;
        Expression scope = call.getScope().get();
        if (scope.isNameExpr() && (flow.locals.containsKey(scope.toString()) || currentType != null && project.field(currentType, scope.toString()) != null)) return false;
        return currentType != null && types.contains(project.qualify(scope.toString(), currentType));
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
        if (access instanceof ArrayAccessExpr) {
            dereference(access, scope, receiver, flow, Sink.ARRAY);
        } else if (access instanceof FieldAccessExpr field && receiver.nullness() != Nullness.NON_NULL
            && isInstanceField(receiver.type(), field)) {
            dereference(access, scope, receiver, flow, receiver.type().isArrayType() ? Sink.ARRAY_LENGTH : Sink.FIELD);
        }
        if (project != null && access instanceof FieldAccessExpr field) {
            String key = field.toString();
            if (assigned == null && flow.locals.containsKey(key)) return flow.locals.get(key);
            var type = scope.isThisExpr() || scope.isSuperExpr() ? currentType
                : receiver.type() == null ? null : project.types.get(project.qualify(receiver.type().asString(), currentType));
            var declared = project.field(type, field.getNameAsString());
            if (assigned != null) {
                Value updated = declared == null ? result : new Value(SourceParsing.type(project.qualifyType(declared.type(), type)), result.nullness(), result.trace(), result.parameter());
                flow.locals.put(key, updated); return updated;
            }
            if (declared != null) return new Value(SourceParsing.type(project.qualifyType(declared.type(), type)), declared.state());
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
        if (test instanceof BooleanLiteralExpr literal) {
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
            constrain(checked, Nullness.NULL, isNull ? yes : no); constrain(checked, Nullness.NON_NULL, isNull ? no : yes);
        }
        return new Branch(yes, no);
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
            flow.locals.put(name.getNameAsString(), new Value(previous.type(), wanted, previous.trace(), previous.parameter()));
        }
    }

    private boolean isInstanceMethod(Type type, MethodCallExpr call) {
        if (type == null) return false;
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
            trace, left.parameter() == right.parameter() ? left.parameter() : -1);
    }

    private static final class Flow {
        private final Map<String, Value> locals = new HashMap<>();
        private boolean reachable = true;

        private Flow copy() {
            var copy = new Flow();
            copy.replaceWith(this);
            return copy;
        }

        private void replaceWith(Flow other) {
            locals.clear();
            locals.putAll(other.locals);
            reachable = other.reachable;
        }

        private void forgetValues() {
            locals.replaceAll((name, value) -> new Value(value.type(), Nullness.UNKNOWN));
        }

        private static Flow merge(Flow left, Flow right) {
            if (!left.reachable) return right;
            if (!right.reachable) return left;
            Flow result = left.copy();
            result.locals.replaceAll((name, value) -> {
                Value other = right.locals.getOrDefault(name, UNKNOWN);
                return value == other ? value : mergeValue(value, other);
            });
            return result;
        }
    }
}
