package com.binaryscan.checker.java;

import com.github.javaparser.ast.*;
import com.github.javaparser.ast.body.*;
import com.github.javaparser.ast.expr.*;
import com.github.javaparser.ast.stmt.*;
import java.io.IOException;
import java.nio.file.Files;
import java.util.*;
import java.util.regex.Pattern;
import static com.binaryscan.checker.java.SecurityAnalysis.*;

/** Bounded symbolic source-to-sink analysis. It never executes analyzed code. */
final class SecurityFlow {
    private static final int ROUNDS=10,TRACE=24,MAX_SINKS=256;
    private final ProjectContext project;private final Set<String> enabled;private final SecurityResources resources;
    private final Map<String,Method> methods=new LinkedHashMap<>();private final Map<String,Summary> summaries=new LinkedHashMap<>();
    private final Map<String,Integer> revisions=new HashMap<>();
    private final Map<String,Map<String,Integer>> dependencies=new HashMap<>();
    private final Set<String> uncachedMethods=new HashSet<>();
    private String activeMethod;private int dependencyEdges,cachedSummaries;
    private final Map<String,Expression> fields=new HashMap<>();private final Map<String,Models.Finding> findings=new LinkedHashMap<>();
    private final Set<String> immutableLiteralEnums=new HashSet<>();
    private final Set<String> callSites=new HashSet<>(),unknownSites=new HashSet<>();private boolean truncated;private final List<SecurityResources.Location> jwtBindings=new ArrayList<>();
    record Method(String key,String path,ProjectContext.TypeInfo owner,MethodDeclaration node,boolean entry,boolean verifier) {}
    record Sink(String kind,SecurityResources.Location site,Fact value,List<SecurityResources.Location> related) {}
    record Summary(Fact returned,List<Sink> sinks,Map<Integer,Fact> effects) {
        String fingerprint(){return (returned==null?"":returned.key())+sinks.stream().map(s->s.kind+":"+s.site.path()+":"+s.site.line()+":"+s.value.key()).sorted().toList()+effects.entrySet().stream().map(x->x.getKey()+":"+x.getValue().key()).sorted().toList();}
    }
    static final class Fact {
        String type="",constant,id="",prefix="";Set<Integer> parameters=Set.of();boolean web,scalar,safeSql,broad,unsafeValidator,loaded,rawSql,transformed,uncertain,safeFlow=true;int typingMutation;
        List<SecurityResources.Location> trace=List.of();List<Fact> elements=List.of();
        Fact(){}Fact(String type){this.type=type==null?"":type;scalar=scalarType(this.type);safeSql=scalar;}
        Fact copy(){var f=new Fact(type);f.constant=constant;f.id=id;f.prefix=prefix;f.parameters=parameters;f.web=web;f.scalar=scalar;f.safeSql=safeSql;f.broad=broad;f.unsafeValidator=unsafeValidator;f.loaded=loaded;f.rawSql=rawSql;f.transformed=transformed;f.uncertain=uncertain;f.trace=trace;f.elements=elements;f.typingMutation=typingMutation;f.safeFlow=safeFlow;return f;}
        Fact type(String t){var f=copy();f.type=t==null?"":t;f.scalar=scalarType(f.type);if(f.scalar)f.safeSql=true;return f;}
        Fact step(SecurityResources.Location s){var f=copy();if(!trace.contains(s)&&trace.size()<TRACE){var all=new ArrayList<>(trace);all.add(s);f.trace=List.copyOf(all);}return f;}
        boolean input(){return web||!parameters.isEmpty();}boolean unsafeSql(){return input()&&!safeSql&&!scalar;}
        String key(){return type+":"+constant+":"+prefix+":"+new TreeSet<>(parameters)+":"+web+":"+safeSql+":"+broad+":"+unsafeValidator+":"+loaded+":"+rawSql+":"+transformed+":"+uncertain+":"+typingMutation+":"+safeFlow+":"+elements.stream().limit(8).map(Fact::key).toList();}
        Fact substitute(List<Fact> args){var f=copy();f.parameters=Set.of();var traces=new ArrayList<SecurityResources.Location>();for(int p:parameters)if(p<args.size()){var a=args.get(p);f.web|=a.web;var ps=new TreeSet<>(f.parameters);ps.addAll(a.parameters);f.parameters=Set.copyOf(ps);f.uncertain|=a.uncertain;traces.addAll(a.trace);if(!transformed&&parameters.size()==1){f.constant=a.constant;f.prefix=a.prefix;f.safeSql|=a.safeSql;f.scalar|=a.scalar;f.broad|=a.broad;f.loaded|=a.loaded;f.rawSql|=a.rawSql;if(f.type.isEmpty()||f.type.equals("java.lang.Object"))f.type=a.type;}}
            if(safeFlow&&!parameters.isEmpty()&&parameters.stream().allMatch(p->p<args.size()&&(!args.get(p).input()||args.get(p).safeSql||args.get(p).scalar)))f.safeSql=true;
            for(var t:trace)if(!traces.contains(t))traces.add(t);f.trace=List.copyOf(traces.subList(0,Math.min(TRACE,traces.size())));f.elements=elements.stream().map(e->e.substitute(args)).toList();if(typingMutation<0)f.broad=false;return f;}
    }
    private static Fact combine(List<Fact> values){Fact out=null;for(var f:values)out=out==null?f.copy():merge(out,f);return out==null?new Fact():out;}
    private static Fact merge(Fact a,Fact b){var f=a.copy();var p=new TreeSet<>(a.parameters);p.addAll(b.parameters);f.parameters=Set.copyOf(p);f.web|=b.web;f.broad|=b.broad;f.loaded|=b.loaded;f.unsafeValidator|=b.unsafeValidator;f.rawSql|=b.rawSql;f.uncertain|=b.uncertain;f.safeFlow&=b.safeFlow;f.safeSql=(!a.input()||a.safeSql)&&(!b.input()||b.safeSql);f.scalar&=b.scalar;f.transformed|=b.transformed;f.typingMutation=a.typingMutation==b.typingMutation?a.typingMutation:a.typingMutation==1||b.typingMutation==1?1:0;f.constant=Objects.equals(a.constant,b.constant)?a.constant:null;f.id=a.id.equals(b.id)?a.id:"";f.prefix=commonPrefix(a.constant!=null?a.constant:a.prefix,b.constant!=null?b.constant:b.prefix);if(f.type.isEmpty())f.type=b.type;for(var t:b.trace)f=f.step(t);if(!a.elements.equals(b.elements))f.elements=List.of();return f;}
    private static String commonPrefix(String a,String b){int i=0;while(i<a.length()&&i<b.length()&&a.charAt(i)==b.charAt(i))i++;return a.substring(0,i);}
    static final class Env {
        final Method method;final Map<String,Fact> locals=new HashMap<>(),heap=new HashMap<>();final List<Sink> sinks=new ArrayList<>();
        Fact returned,guard=new Fact();boolean bypass,verified,dead;int statements;
        Env(Method method){this.method=method;}
        Env copy(){var e=new Env(method);e.locals.putAll(locals);e.heap.putAll(heap);e.guard=guard;e.bypass=bypass;e.verified=verified;e.statements=statements;return e;}
        Fact actual(Fact f){return f.id.isEmpty()?f:heap.getOrDefault(f.id,f);}
        void sink(Sink s){if(sinks.size()<MAX_SINKS)sinks.add(s);}
    }
    SecurityFlow(ProjectContext project,Set<String> enabled,SecurityResources resources){this.project=project;this.enabled=enabled;this.resources=resources;}
    SecurityAnalysis analyze(List<ProjectAnalyzer.Input> inputs)throws IOException{
        for(var input:inputs){project.checkBudget();var unit=SourceParsing.parse(Files.readString(input.file()));
            for(TypeDeclaration<?> declaration:unit.findAll(TypeDeclaration.class)){var owner=project.types.get(ProjectContext.qualifiedName(declaration,unit.getPackageDeclaration().map(p->p.getNameAsString()).orElse("")));if(owner==null||owner.external||!owner.path.equals(input.path()))continue;
                if(declaration instanceof EnumDeclaration enumeration&&enumeration.getEntries().stream().allMatch(v->v.getClassBody().isEmpty()&&v.getArguments().stream().allMatch(a->a instanceof LiteralExpr))
                    &&enumeration.getFields().stream().filter(f->!f.isStatic()).allMatch(f->f.isFinal()&&f.getVariables().stream().allMatch(v->v.getType().isPrimitiveType()||project.qualify(v.getTypeAsString(),owner).equals("java.lang.String"))))immutableLiteralEnums.add(owner.name);
                for(var field:declaration.getFields())if(field.isFinal())for(var variable:field.getVariables())variable.getInitializer().ifPresent(e->fields.put(owner.name+"#"+variable.getNameAsString(),e));
                for(var node:declaration.getMethods()){var info=project.method(node,unit);if(info==null)continue;boolean entry=entry(node,declaration,owner);boolean verifier=node.findAll(MethodCallExpr.class).stream().anyMatch(c->credentialVerifier(c,owner));
                    Method m=new Method(info.key,input.path(),owner,node,entry,verifier);methods.putIfAbsent(info.key,m);
                    for(var annotation:node.getAnnotations())if(Set.of("org.apache.ibatis.annotations.Select","org.apache.ibatis.annotations.Insert","org.apache.ibatis.annotations.Update","org.apache.ibatis.annotations.Delete").contains(project.qualify(annotation.getNameAsString(),owner))){
                        var slots=resources.sql.computeIfAbsent(owner.name+"#"+node.getNameAsString(),ignored->new ArrayList<>());for(var literal:annotation.findAll(StringLiteralExpr.class)){var matcher=SecurityResources.SLOT.matcher(literal.asString());while(matcher.find())slots.add(new SecurityResources.SqlSlot(matcher.group(1).strip(),site(m,literal,"sql-template","raw MyBatis annotation substitution")));}
                    }
                    for(var creation:node.findAll(ObjectCreationExpr.class))if(project.qualify(creation.getTypeAsString(),owner).startsWith("cn.dev33.satoken.jwt.StpLogicJwt"))jwtBindings.add(site(m,creation,"binding","source configures JWT token logic"));
                }
            }
        }
        boolean converged=false;int rounds=0;
        for(;rounds<ROUNDS;rounds++){
            boolean changed=false;
            for(var m:methods.values()){
                project.checkBudget();var previous=summaries.get(m.key);var deps=dependencies.get(m.key);
                if(previous!=null&&!uncachedMethods.contains(m.key)&&deps!=null&&deps.entrySet().stream().allMatch(d->Objects.equals(revisions.getOrDefault(d.getKey(),0),d.getValue()))){cachedSummaries++;continue;}
                activeMethod=m.key;if(deps!=null)dependencyEdges-=deps.size();dependencies.put(m.key,new HashMap<>());
                Summary next=run(m);summaries.put(m.key,next);
                if(previous==null||!previous.fingerprint().equals(next.fingerprint())){changed=true;revisions.merge(m.key,1,Integer::sum);}
            }
            activeMethod=null;if(!changed){converged=true;break;}
        }
        if(!converged){truncated=true;project.diagnostics.put("security-rounds",new Models.Diagnostic("JAVA_SECURITY_CONTEXT_LIMIT","",1,1,"security dataflow reached ten summary rounds; long or recursive paths may be incomplete"));}
        // Actual HTTP entries instantiate symbolic parameter dependencies. Other
        // methods emit only independently established request/configuration sources.
        for(boolean entries:List.of(true,false))for(var m:methods.values())if(m.entry==entries){var summary=summaries.get(m.key);if(summary==null)continue;var args=new ArrayList<Fact>();for(var parameter:m.node.getParameters()){
            Fact value=new Fact(project.qualifyType(parameter.getTypeAsString(),m.owner));if(entries&&boundParameter(parameter,m)){value.web=true;value=value.step(site(m,parameter,"source","HTTP-bound input"));}args.add(value);
        }args.add(new Fact(m.owner.name));for(var sink:summary.sinks)emit(new Sink(sink.kind,sink.site,sink.value.substitute(args),sink.related),entries);}
        if(enabled.contains(JWT))for(var key:resources.jwtKeys){var evidence=new LinkedHashMap<String,Object>();evidence.put("ruleFamily",JWT);evidence.put("securityModelVersion",VERSION);evidence.put("certainty","configuration-risk");evidence.put("runtimeOverride","unknown");evidence.put("secretValue","[REDACTED]");evidence.put("redactSnippet",true);evidence.put("bindingLocations",jwtBindings.stream().limit(16).map(SecurityResources.Location::evidence).toList());evidence.put("securityTrace",List.of(key.evidence()));add(JWT,key,"打包配置包含固定 JWT 签名密钥或固定回退值；需核对生效配置与轮换，不能据此确认认证失陷",evidence);}
        var metrics=new LinkedHashMap<String,Object>();metrics.put("version",VERSION);metrics.put("methods",methods.size());metrics.put("summaryRounds",Math.min(ROUNDS,rounds+1));metrics.put("callSites",callSites.size());metrics.put("unknownCallSites",unknownSites.size());metrics.put("truncated",truncated);metrics.put("resourceStatements",resources.sql.size());metrics.put("configurationCandidates",resources.jwtKeys.size());metrics.put("cachedSummaries",cachedSummaries);metrics.put("summaryDependencyEdges",dependencyEdges);
        return new SecurityAnalysis(List.copyOf(findings.values()),Map.copyOf(metrics));
    }
    private Summary summary(String method){
        if(activeMethod!=null&&!uncachedMethods.contains(activeMethod)){
            var deps=dependencies.get(activeMethod);
            if(!deps.containsKey(method)){
                if(dependencyEdges>=ProjectContext.EDGE_LIMIT){dependencyEdges-=deps.size();deps.clear();uncachedMethods.add(activeMethod);}
                else{deps.put(method,revisions.getOrDefault(method,0));dependencyEdges++;}
            }
        }
        return summaries.get(method);
    }
    private Summary run(Method m){var env=new Env(m);for(int i=0;i<m.node.getParameters().size();i++){var p=m.node.getParameter(i);var f=new Fact(project.qualifyType(p.getTypeAsString(),m.owner));f.parameters=Set.of(i);f.id=m.key+":p"+i;env.locals.put(p.getNameAsString(),f);}
        m.node.getBody().ifPresent(body->walk(body,env));var unique=new LinkedHashMap<String,Sink>();for(var sink:env.sinks){String key=sink.kind+":"+sink.site+":"+sink.value.key();if(unique.size()<MAX_SINKS)unique.putIfAbsent(key,sink);else truncated=true;}
        if(truncated)project.diagnostics.putIfAbsent("security-sinks",new Models.Diagnostic("JAVA_SECURITY_FACT_LIMIT",m.path,1,1,"bounded security flow facts were truncated; some paths may be incomplete"));
        var effects=new LinkedHashMap<Integer,Fact>();for(int i=0;i<m.node.getParameters().size();i++){Fact changed=env.heap.get(m.key+":p"+i);if(changed!=null&&(changed.rawSql||changed.typingMutation!=0))effects.put(i,changed);}
        return new Summary(env.returned,List.copyOf(unique.values()),Map.copyOf(effects));}
    private void walk(Statement statement,Env e){if(e.dead)return;if(++e.statements>10000){truncated=true;return;}project.checkBudget();
        switch(statement){
            case BlockStmt b->{for(var s:b.getStatements())walk(s,e);}
            case ExpressionStmt s->eval(s.getExpression(),e);
            case ReturnStmt r->{if(r.getExpression().isPresent()){Fact value=eval(r.getExpression().get(),e);e.returned=e.returned==null?value:merge(e.returned,value);if("true".equals(value.constant)&&e.bypass&&!e.verified&&e.method.verifier)e.sink(new Sink(AUTH_BYPASS,site(e.method,r,"authentication","special input branch returns authentication success without the ordinary verifier"),e.guard,List.of()));}e.dead=true;}
            case ThrowStmt t->{eval(t.getExpression(),e);e.dead=true;}
            case IfStmt branch->{eval(branch.getCondition(),e);var yes=e.copy();var no=e.copy();applyGuards(branch.getCondition(),true,yes);applyGuards(branch.getCondition(),false,no);Fact trigger=trigger(branch.getCondition(),e);yes.guard=merge(yes.guard,trigger);yes.bypass|=trigger.input()&&!requiresVerifier(branch.getCondition(),e.method.owner);walk(branch.getThenStmt(),yes);branch.getElseStmt().ifPresent(s->walk(s,no));join(e,yes,no);if(yes.dead&&negatedVerifier(branch.getCondition(),e.method.owner)||no.dead&&credentialVerifierExpr(branch.getCondition(),e.method.owner))e.verified=true;}
            case TryStmt t->{var attempted=e.copy();for(var resource:t.getResources())eval(resource,attempted);walk(t.getTryBlock(),attempted);var alternatives=new ArrayList<Env>();alternatives.add(attempted);for(var c:t.getCatchClauses()){var caught=e.copy();walk(c.getBody(),caught);alternatives.add(caught);}var joined=alternatives.getFirst();for(int i=1;i<alternatives.size();i++){var next=e.copy();join(next,joined,alternatives.get(i));joined=next;}copyState(e,joined);t.getFinallyBlock().ifPresent(b->{e.dead=false;walk(b,e);});}
            case ForStmt f->{f.getInitialization().forEach(x->eval(x,e));f.getCompare().ifPresent(x->eval(x,e));var loop=e.copy();walk(f.getBody(),loop);f.getUpdate().forEach(x->eval(x,loop));join(e,e.copy(),loop);}
            case ForEachStmt f->{Fact iterable=eval(f.getIterable(),e);var loop=e.copy();for(var v:f.getVariable().getVariables())loop.locals.put(v.getNameAsString(),iterable.type(project.qualifyType(v.getTypeAsString(),e.method.owner)));walk(f.getBody(),loop);join(e,e.copy(),loop);}
            case WhileStmt w->{eval(w.getCondition(),e);var loop=e.copy();walk(w.getBody(),loop);join(e,e.copy(),loop);}
            case DoStmt d->{walk(d.getBody(),e);eval(d.getCondition(),e);}
            case SynchronizedStmt s->{eval(s.getExpression(),e);walk(s.getBody(),e);}
            case SwitchStmt s->{eval(s.getSelector(),e);Env merged=null;for(var entry:s.getEntries()){var branch=e.copy();for(var child:entry.getStatements())walk(child,branch);branch.dead=false;if(merged==null)merged=branch;else{var n=e.copy();join(n,merged,branch);merged=n;}}if(merged!=null)copyState(e,merged);}
            case LabeledStmt l->walk(l.getStatement(),e);
            default->{for(var x:statement.getChildNodes())if(x instanceof Expression expression)eval(expression,e);}
        }
    }
    private static void copyState(Env to,Env from){to.locals.clear();to.locals.putAll(from.locals);to.heap.clear();to.heap.putAll(from.heap);to.sinks.addAll(from.sinks);to.returned=from.returned;to.dead=from.dead;to.guard=from.guard;to.bypass=from.bypass;to.verified=from.verified;}
    private static Fact branchFact(Fact a,Fact b,boolean aDead,boolean bDead){
        if(aDead&&!bDead)return b==null?new Fact():b;
        if(bDead&&!aDead)return a==null?new Fact():a;
        if(a==null)return b==null?new Fact():merge(new Fact(b.type),b);
        return b==null?merge(a,new Fact(a.type)):merge(a,b);
    }
    private static void join(Env target,Env a,Env b){
        var locals=new HashMap<String,Fact>();var names=new HashSet<>(a.locals.keySet());names.addAll(b.locals.keySet());
        for(String name:names)locals.put(name,branchFact(a.locals.get(name),b.locals.get(name),a.dead,b.dead));
        var heap=new HashMap<String,Fact>();names=new HashSet<>(a.heap.keySet());names.addAll(b.heap.keySet());
        for(String name:names){
            var left=a.heap.get(name);var right=b.heap.get(name);
            if(left==null)left=a.locals.values().stream().filter(Objects::nonNull).filter(f->f.id.equals(name)).findFirst().orElse(null);
            if(right==null)right=b.locals.values().stream().filter(Objects::nonNull).filter(f->f.id.equals(name)).findFirst().orElse(null);
            heap.put(name,branchFact(left,right,a.dead,b.dead));
        }
        target.locals.clear();target.locals.putAll(locals);target.heap.clear();target.heap.putAll(heap);
        target.sinks.addAll(a.sinks);target.sinks.addAll(b.sinks);
        target.returned=a.returned==null?b.returned:b.returned==null?a.returned:merge(a.returned,b.returned);
        target.dead=a.dead&&b.dead;target.verified=a.dead&&!b.dead?b.verified:b.dead&&!a.dead?a.verified:a.verified&&b.verified;
    }
    private Fact eval(Expression expression,Env e){if(expression==null)return new Fact();
        if(expression instanceof EnclosedExpr x)return eval(x.getInner(),e);if(expression instanceof CastExpr x)return eval(x.getExpression(),e).type(project.qualifyType(x.getTypeAsString(),e.method.owner));
        if(expression instanceof StringLiteralExpr s){var f=new Fact("java.lang.String");f.constant=s.asString();return f;}if(expression instanceof TextBlockLiteralExpr s){var f=new Fact("java.lang.String");f.constant=s.getValue();return f;}
        if(expression instanceof BooleanLiteralExpr b){var f=new Fact("boolean");f.constant=Boolean.toString(b.getValue());return f;}if(expression instanceof IntegerLiteralExpr||expression instanceof LongLiteralExpr||expression instanceof DoubleLiteralExpr){var f=new Fact("long");f.constant=expression.toString();return f;}
        if(expression instanceof NullLiteralExpr)return new Fact();if(expression instanceof ClassExpr c){var f=new Fact("java.lang.Class");f.constant=project.qualifyType(c.getTypeAsString(),e.method.owner);return f;}
        if(expression instanceof ThisExpr){var f=new Fact(e.method.owner.name);f.parameters=Set.of(e.method.node.getParameters().size());return f;}
        if(expression instanceof NameExpr n){Fact local=e.locals.get(n.getNameAsString());if(local!=null)return e.actual(local);var field=project.field(e.method.owner,n.getNameAsString());if(field!=null){Fact f=constantField(e.method.owner,n.getNameAsString(),e,new HashSet<>());if(f.constant==null&&!field.isStatic())f.parameters=Set.of(e.method.node.getParameters().size());return f.type(project.qualifyType(field.type(),e.method.owner));}return new Fact(project.qualify(n.getNameAsString(),e.method.owner));}
        if(expression instanceof FieldAccessExpr f){var receiver=eval(f.getScope(),e);String owner=project.qualify(receiver.type,e.method.owner);String full=f.toString();if(full.endsWith("LaissezFaireSubTypeValidator.instance")){var value=new Fact("com.fasterxml.jackson.databind.jsontype.impl.LaissezFaireSubTypeValidator");value.unsafeValidator=true;return value;}if(full.endsWith("DefaultTyping.NON_FINAL")||full.endsWith("DefaultTyping.EVERYTHING")||full.endsWith("DefaultTyping.OBJECT_AND_NON_CONCRETE")){var value=new Fact("java.lang.Enum");value.constant=f.getNameAsString();return value;}var type=project.types.get(owner);if(type!=null){var field=project.field(type,f.getNameAsString());if(field!=null){var value=constantField(type,f.getNameAsString(),e,new HashSet<>());if(value.constant!=null)return value;return receiver.type(project.qualifyType(field.type(),type));}}return receiver;}
        if(expression instanceof VariableDeclarationExpr declaration){Fact result=new Fact();for(var variable:declaration.getVariables()){Fact value=variable.getInitializer().map(x->eval(x,e)).orElseGet(Fact::new);String type=project.qualifyType(variable.getTypeAsString(),e.method.owner);if(!type.equals("var"))value=value.type(type);e.locals.put(variable.getNameAsString(),value);result=value;}return result;}
        if(expression instanceof AssignExpr a){Fact value=eval(a.getValue(),e);if(a.getOperator()!=AssignExpr.Operator.ASSIGN)value=merge(eval(a.getTarget(),e),value);String target=a.getTarget().toString();Fact old=e.locals.get(target);if(old!=null)value=value.type(old.type);e.locals.put(target,value);return value;}
        if(expression instanceof BinaryExpr b){Fact a=eval(b.getLeft(),e),right=eval(b.getRight(),e);Fact result=merge(a,right);if(b.getOperator()==BinaryExpr.Operator.PLUS){result.transformed=true;result.prefix=a.constant!=null?a.constant+(right.constant!=null?right.constant:right.prefix):a.prefix;if(a.constant!=null&&right.constant!=null)result.constant=a.constant+right.constant;result.type="java.lang.String";}else result=result.type("boolean");return result;}
        if(expression instanceof ConditionalExpr c){eval(c.getCondition(),e);var yes=e.copy();var no=e.copy();Fact result=merge(eval(c.getThenExpr(),yes),eval(c.getElseExpr(),no));join(e,yes,no);return result;}
        if(expression instanceof UnaryExpr u){Fact value=eval(u.getExpression(),e);if(u.getOperator()==UnaryExpr.Operator.LOGICAL_COMPLEMENT){value=value.copy();if(value.constant!=null)value.constant=Boolean.toString(!Boolean.parseBoolean(value.constant));}return value;}
        if(expression instanceof ArrayInitializerExpr a){var f=combine(a.getValues().stream().map(v->eval(v,e)).toList());f.elements=a.getValues().stream().map(v->eval(v,e)).toList();return f;}
        if(expression instanceof ArrayCreationExpr a){Fact f=a.getInitializer().map(x->eval(x,e)).orElseGet(Fact::new);return f.type(a.createdType().asString());}
        if(expression instanceof ArrayAccessExpr a)return eval(a.getName(),e);
        if(expression instanceof ObjectCreationExpr c)return creation(c,e);
        if(expression instanceof MethodCallExpr call)return call(call,e);
        if(expression instanceof LambdaExpr lambda){var nested=e.copy();var inferred=lambdaParameters(lambda,e);for(int i=0;i<lambda.getParameters().size();i++){var p=lambda.getParameter(i);String type=p.getType().isUnknownType()&&i<inferred.size()?inferred.get(i):project.qualifyType(p.getTypeAsString(),e.method.owner);nested.locals.put(p.getNameAsString(),new Fact(type));}if(lambda.getBody() instanceof ExpressionStmt s)eval(s.getExpression(),nested);else walk(lambda.getBody(),nested);e.sinks.addAll(nested.sinks);return new Fact();}
        return new Fact();
    }
    private List<String> lambdaParameters(LambdaExpr lambda,Env env){
        Node parent=lambda.getParentNode().orElse(null);while(parent instanceof EnclosedExpr)parent=parent.getParentNode().orElse(null);
        String type=parent instanceof ReturnStmt?env.method.node.getTypeAsString():parent instanceof VariableDeclarator variable?variable.getTypeAsString():"";
        var functional=project.types.get(project.qualify(type,env.method.owner));if(functional==null||!functional.isInterface)return List.of();
        var signatures=functional.methods.stream().filter(m->!m.isStatic&&!m.body&&m.parameters.size()==lambda.getParameters().size()).toList();
        if(signatures.size()!=1)return List.of();var method=signatures.getFirst();return method.parameters.stream().map(p->project.qualifyType(p,functional)).toList();
    }
    private Fact constantField(ProjectContext.TypeInfo owner,String name,Env e,Set<String> seen){String key=owner.name+"#"+name;if(!seen.add(key)||seen.size()>32)return new Fact();Expression value=fields.get(key);if(value instanceof StringLiteralExpr s){var f=new Fact("java.lang.String");f.constant=s.asString();return f;}if(value instanceof NameExpr n)return constantField(owner,n.getNameAsString(),e,seen);if(value instanceof BinaryExpr b&&b.getOperator()==BinaryExpr.Operator.PLUS){Fact l=literalOrField(b.getLeft(),owner,e,seen),r=literalOrField(b.getRight(),owner,e,seen);if(l.constant!=null&&r.constant!=null){l.constant+=r.constant;return l;}}return new Fact();}
    private Fact literalOrField(Expression x,ProjectContext.TypeInfo owner,Env e,Set<String> seen){if(x instanceof StringLiteralExpr s){var f=new Fact("java.lang.String");f.constant=s.asString();return f;}if(x instanceof NameExpr n)return constantField(owner,n.getNameAsString(),e,new HashSet<>(seen));return new Fact();}
    private Fact creation(ObjectCreationExpr c,Env e){String type=project.qualify(c.getTypeAsString(),e.method.owner);List<Fact> args=c.getArguments().stream().map(x->eval(x,e)).toList();var f=new Fact(project.qualifyType(c.getTypeAsString(),e.method.owner));f.id=e.method.path+"@"+c.getBegin().orElseThrow();
        var constructorInputs=combine(args);f.web=constructorInputs.web;f.parameters=constructorInputs.parameters;f.trace=constructorInputs.trace;f.uncertain=constructorInputs.uncertain;f.safeFlow=false;f.safeSql=f.scalar;
        if(type.equals("java.lang.ProcessBuilder")){f.elements=args.size()==1&&!args.getFirst().elements.isEmpty()?args.getFirst().elements:args;f.trace=combine(args).trace;}
        if(type.startsWith("org.redisson.codec.")||type.startsWith("org.redisson.client.codec.")){var config=combine(args);f.broad=config.broad;f.trace=config.trace;f=f.step(site(e.method,c,"codec","configured mapper is passed into a Redis codec"));}
        if(type.equals("com.fasterxml.jackson.databind.ObjectMapper")||type.equals("com.fasterxml.jackson.databind.json.JsonMapper"))f.broad=false;
        e.heap.put(f.id,f);return f;
    }
    private Fact call(MethodCallExpr c,Env e){callSites.add(e.method.path+":"+c.getBegin());String name=c.getNameAsString();Fact receiver=c.getScope().map(s->eval(s,e)).orElseGet(()->new Fact(e.method.owner.name));List<Fact> args=c.getArguments().stream().map(x->eval(x,e)).toList();receiver=e.actual(receiver);String owner=project.qualify(receiver.type,e.method.owner);
        if(requestType(owner)&&Set.of("getParameter","getParameterValues","getParameterMap","getHeader","getHeaders","getInputStream","getReader","getQueryString","getCookies","getBody").contains(name)){var f=new Fact(name.endsWith("Stream")?"java.io.InputStream":"java.lang.String");f.web=true;return f.step(site(e.method,c,"source","request data is read"));}
        if((owner.equals("java.io.BufferedReader")||owner.equals("java.io.InputStream")||owner.equals("java.util.Scanner"))&&Set.of("readLine","read","readAllBytes","nextLine").contains(name))return receiver.type(name.equals("readAllBytes")?"byte[]":"java.lang.String");
        if(owner.equals("java.lang.Runtime")&&name.equals("getRuntime"))return new Fact("java.lang.Runtime");
        if(owner.equals("java.lang.invoke.MethodHandles")&&Set.of("lookup","privateLookupIn","publicLookup").contains(name))return new Fact("java.lang.invoke.MethodHandles.Lookup");
        if(owner.equals("java.lang.Class")&&name.equals("forName")&&!args.isEmpty()){var f=new Fact("java.lang.Class");f.constant=args.getFirst().constant;return f;}
        if(immutableLiteralEnums.contains(owner)&&name.equals("valueOf")&&args.size()==1)return new Fact(owner).step(site(e.method,c,"validation","a validated enum name selects immutable literal declaration data"));
        if((owner.equals("java.net.URL")&&name.equals("openStream"))||(owner.equals("java.net.URLConnection")||owner.equals("java.net.HttpURLConnection"))&&name.equals("getInputStream")){var f=new Fact("java.io.InputStream");f.web=true;return f.step(site(e.method,c,"source","network response bytes are read; content trust has not been established"));}
        if(owner.equals("javax.script.ScriptEngineManager")&&name.startsWith("getEngineBy"))return new Fact("javax.script.ScriptEngine");
        if(owner.equals("java.lang.Runtime")&&name.equals("exec")&&!args.isEmpty()){Fact dangerous=command(args.getFirst().elements.isEmpty()?List.of(args.getFirst()):args.getFirst().elements);execution(c,dangerous,e,"command");return new Fact("java.lang.Process");}
        if(owner.equals("java.lang.ProcessBuilder")){if(name.equals("command")){var updated=receiver.copy();updated.elements=args.size()==1&&!args.getFirst().elements.isEmpty()?args.getFirst().elements:args;e.heap.put(updated.id,updated);return updated;}if(name.equals("start")){execution(c,command(receiver.elements),e,"command");return new Fact("java.lang.Process");}}
        if((owner.equals("javax.script.ScriptEngine")||project.inherits(owner,"javax.script.ScriptEngine",e.method.owner)||owner.endsWith(".ELProcessor")||owner.endsWith(".ExpressionFactory"))&&Set.of("eval","createValueExpression","createMethodExpression").contains(name)&&!args.isEmpty()){execution(c,owner.endsWith(".ExpressionFactory")&&args.size()>1?args.get(1):args.getFirst(),e,"script");return new Fact();}
        if((owner.equals("org.springframework.expression.spel.standard.SpelExpressionParser")||project.inherits(owner,"org.springframework.expression.ExpressionParser",e.method.owner))&&name.equals("parseExpression")&&!args.isEmpty()){Fact f=args.getFirst().type("org.springframework.expression.Expression");f.transformed=true;return f.step(site(e.method,c,"expression","text is parsed as an expression"));}
        if((owner.equals("org.springframework.expression.Expression")||project.inherits(owner,"org.springframework.expression.Expression",e.method.owner))&&Set.of("getValue","setValue").contains(name)){execution(c,receiver,e,"script");return new Fact();}
        if(Set.of("defineClass","defineHiddenClass","defineHiddenClassWithClassData","defineAnonymousClass").contains(name)&&classDefiner(owner,e.method.owner)){
            Fact bytes=combine(args.stream().filter(f->f.type.contains("byte")||f.input()).toList());if(bytes.input())e.sink(new Sink(CLASS_LOAD,site(e.method,c,"class-definition","untrusted bytes reach dynamic class definition"),bytes,List.of()));Fact f=bytes.type("java.lang.Class");f.loaded=true;return f;
        }
        if(registration(owner,name,e.method.owner)){
            Fact payload=combine(args);boolean handler=args.stream().anyMatch(f->dangerousHandler(f.type));
            if(payload.loaded||handler||e.guard.input()&&payload.input())e.sink(new Sink(WEB_IMPLANT,site(e.method,c,"registration","web component registration is associated with an untrusted class, dangerous handler or input-controlled trigger"),merge(payload,e.guard),List.of()));
        }
        if(authLogin(owner,name)&&e.bypass&&!e.verified)e.sink(new Sink(AUTH_BYPASS,site(e.method,c,"authentication","special input branch establishes identity without the ordinary credential check"),e.guard,List.of()));
        if((owner.equals("cn.dev33.satoken.config.SaTokenConfig")||owner.contains("Jwt"))&&Set.of("setJwtSecretKey","setSecret","setSigningKey").contains(name)&&!args.isEmpty()&&SecurityResources.literalSecret(args.getFirst().constant))e.sink(new Sink(JWT,site(e.method,c,"configuration","literal JWT signing key is assigned; value redacted"),new Fact(),List.of()));
        if(objectMapper(owner,e.method.owner)){
            if(name.equals("activateDefaultTyping")||name.equals("activateDefaultTypingAsProperty")||name.equals("enableDefaultTyping")||name.equals("enableDefaultTypingAsProperty")){
                var f=receiver.copy();f.broad=name.startsWith("enable")||!args.isEmpty()&&args.getFirst().unsafeValidator;f.typingMutation=f.broad?1:-1;f=f.step(site(e.method,c,"configuration","mapper configures polymorphic typing and its validator"));if(!f.id.isEmpty())e.heap.put(f.id,f);return f;
            }
            if(name.equals("deactivateDefaultTyping")){var f=receiver.copy();f.broad=false;f.typingMutation=-1;if(!f.id.isEmpty())e.heap.put(f.id,f);return f;}
            if(Set.of("readValue","readTree","convertValue").contains(name)&&(receiver.broad||receiver.input()))e.sink(new Sink(JACKSON,site(e.method,c,"deserialization","a mapper with unrestricted polymorphic typing is used to decode values"),receiver,List.of()));
            if(name.equals("copy")){var f=receiver.copy();f.id=e.method.path+"@"+c.getBegin().orElseThrow();e.heap.put(f.id,f);return f;}
        }
        if(owner.startsWith("org.redisson.")&&name.equals("setCodec")&&!args.isEmpty()&&(args.getFirst().broad||args.getFirst().input()))e.sink(new Sink(JACKSON,site(e.method,c,"codec-use","Redis is configured to use an unrestricted polymorphic codec"),args.getFirst(),List.of()));
        if(wrapper(owner,e.method.owner)){
            if(Set.of("apply","last","exists","notExists","inSql","notInSql","eqSql","gtSql","geSql","ltSql","leSql","having","orderByAsc","orderByDesc","select").contains(name)){
                int index=!args.isEmpty()&&args.getFirst().type.equals("boolean")?1:0;if(Set.of("inSql","notInSql","eqSql","gtSql","geSql","ltSql","leSql").contains(name))index++;
                if(index<args.size()){Fact sql=args.get(index);if(sql.unsafeSql()){var f=merge(receiver,sql);f.id=receiver.id;f.type=receiver.type;f.rawSql=true;f=f.step(site(e.method,c,"raw-sql","input is inserted into a raw Wrapper SQL fragment"));if(!f.id.isEmpty())e.heap.put(f.id,f);return f;}}
            }
            return receiver;
        }
        if(name.equals("lambdaQuery")||name.equals("query")&&owner.equals("com.baomidou.mybatisplus.core.toolkit.Wrappers")){var f=new Fact("com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper");f.id=e.method.path+"@"+c.getBegin().orElseThrow();e.heap.put(f.id,f);return f;}
        if((mapper(owner,e.method.owner)||mybatisService(owner,e.method.owner))&&queryMethod(name))for(Fact arg:args)if(arg.rawSql||wrapper(arg.type,e.method.owner)&&arg.input())e.sink(new Sink("wrapper-sql",site(e.method,c,"sql-execution","raw input-controlled Wrapper fragment reaches a database query"),arg,List.of()));
        if(Set.of("execute","executeQuery","executeUpdate","executeLargeUpdate","addBatch","prepareStatement","prepareCall","createNativeQuery","createQuery").contains(name)&&!args.isEmpty()&&(owner.startsWith("java.sql.")||owner.startsWith("jakarta.persistence.")||owner.startsWith("javax.persistence.")))
            if(args.getFirst().unsafeSql())e.sink(new Sink("java-sql-injection",site(e.method,c,"sql-execution","input-controlled SQL text reaches a database API"),args.getFirst(),List.of()));
        var targets=targets(e.method.owner,receiver,c,args);Fact returned=null;
        for(var target:targets){Method callee=methods.get(target.key);if(callee==null)continue;xmlSinks(callee,args,c,e);Summary summary=summary(callee.key);if(summary==null)continue;
            var boundArgs=new ArrayList<>(args);boundArgs.add(receiver);
            for(var effect:summary.effects.entrySet())if(effect.getKey()<args.size()){
                Fact argument=e.actual(args.get(effect.getKey()));if(argument.id.isEmpty())continue;Fact change=effect.getValue().substitute(boundArgs);Fact updated=merge(argument,change);updated.id=argument.id;updated.type=argument.type;if(change.typingMutation!=0){updated.broad=change.broad;updated.typingMutation=change.typingMutation;}e.heap.put(updated.id,updated);
            }
            for(var sink:summary.sinks){Fact value=sink.value.substitute(boundArgs).step(site(e.method,c,"call","call to "+callee.owner.name+"."+callee.node.getNameAsString()));e.sink(new Sink(sink.kind,sink.site,value,sink.related));}
            if(summary.returned!=null){var f=summary.returned.substitute(boundArgs).step(site(e.method,c,"return","return from "+callee.owner.name+"."+callee.node.getNameAsString()));if(!f.id.isEmpty()){boolean alias=false;for(int i=0;i<args.size();i++)if(summary.returned.id.equals(callee.key+":p"+i)){f.id=args.get(i).id;alias=true;break;}if(!alias)f.id=e.method.path+"@return:"+c.getBegin();if(!f.id.isEmpty())e.heap.put(f.id,f);}returned=returned==null?f:merge(returned,f);}
        }
        if(returned!=null)return returned;
        if(owner.equals("java.util.Objects")&&name.equals("requireNonNull")&&!args.isEmpty())return args.getFirst();
        if(owner.equals("cn.hutool.core.convert.Convert")&&name.equals("toStr")&&!args.isEmpty()&&project.contracts.supports("cn.hutool:hutool-core")&&project.externalContractsAllowed(owner)){
            Fact converted=combine(args).type("java.lang.String");converted.transformed=true;return converted;
        }
        if(name.equals("getClass")&&args.isEmpty()){var f=new Fact("java.lang.Class");f.constant=receiver.type;return f;}
        if(owner.equals("java.lang.Class")&&Set.of("newInstance","getDeclaredConstructor","getConstructor","getDeclaredMethod","getMethod").contains(name)){var f=receiver.copy();f.type=name.contains("Constructor")?"java.lang.reflect.Constructor":name.contains("Method")?"java.lang.reflect.Method":receiver.constant==null?"java.lang.Object":receiver.constant;if(name.contains("Method")&&!args.isEmpty()&&receiver.constant!=null&&args.getFirst().constant!=null)f.constant=receiver.constant+"#"+args.getFirst().constant;return f;}
        if(owner.equals("java.lang.reflect.Method")&&name.equals("invoke")&&receiver.constant!=null&&receiver.constant.contains("#")){
            String[] target=receiver.constant.split("#",2);Fact input=combine(args);if(Set.of("defineClass","defineHiddenClass","defineAnonymousClass").contains(target[1])&&classDefiner(target[0],e.method.owner)&&input.input()){e.sink(new Sink(CLASS_LOAD,site(e.method,c,"class-definition","untrusted bytes reach a constant-resolved reflective class definition"),input,List.of()));input.loaded=true;return input.type("java.lang.Class");}
            if(registration(target[0],target[1],e.method.owner)&&input.loaded)e.sink(new Sink(WEB_IMPLANT,site(e.method,c,"registration","reflective web registration receives an untrusted defined class"),input,List.of()));return input;
        }
        if((owner.equals("java.lang.reflect.Constructor")||owner.equals("java.lang.reflect.Method"))&&Set.of("newInstance","invoke").contains(name))return receiver;
        if(name.equals("parseLong")||name.equals("parseInt")||name.equals("valueOf")&&Set.of("java.lang.Long","java.lang.Integer","java.lang.Short","java.lang.Double","java.lang.Float","java.math.BigDecimal","java.math.BigInteger").contains(owner))return combine(args).type("long");
        if(name.equals("getBytes")||name.equals("toCharArray"))return receiver.type(name.equals("getBytes")?"byte[]":"char[]");
        if(name.equals("asList")&&owner.equals("java.util.Arrays")||name.equals("of")&&Set.of("java.util.List","java.util.Set").contains(owner)){var f=combine(args).type(owner.equals("java.util.Set")?owner:"java.util.List");f.elements=args;return f;}
        if(name.equals("toString")&&!receiver.type.isEmpty())return receiver.type("java.lang.String");
        if(owner.equals("java.lang.String")&&Set.of("formatted","format","valueOf").contains(name)){
            var values=new ArrayList<>(args);if(name.equals("formatted"))values.add(receiver);Fact result=combine(values).type("java.lang.String");result.transformed=true;
            String format=name.equals("formatted")?receiver.constant:args.isEmpty()?null:args.getFirst().constant;
            if(format!=null&&format.contains("%"))result.prefix=format.substring(0,format.indexOf('%'));
            if(!name.equals("valueOf")&&(format==null||Pattern.compile("%(?:[0-9]+\\$)?[-#+ 0,(]*[0-9]*(?:\\.[0-9]+)?[cC]").matcher(format).find())){result.safeFlow=false;result.safeSql=false;}return result;
        }
        if((owner.equals("java.lang.StringBuilder")||owner.equals("java.lang.StringBuffer"))&&name.equals("append")){var values=new ArrayList<>(args);values.add(receiver);Fact result=combine(values).type(owner);result.id=receiver.id;result.prefix=receiver.constant!=null?receiver.constant:receiver.prefix;result.transformed=true;if(!result.id.isEmpty())e.heap.put(result.id,result);return result;}
        var flows=new ArrayList<Fact>(args);if(receiver.input()||receiver.broad||receiver.loaded)flows.add(receiver);Fact fallback=combine(flows);String result=resultType(targets,e.method.owner,receiver,args);if(result.isEmpty())result=platformResult(owner,name,args.size());if(result.isEmpty()&&name.startsWith("get")&&args.isEmpty())result=getterType(receiver,name,e.method.owner);fallback=fallback.type(result);fallback.transformed=true;fallback.prefix="";
        // Boolean/string predicates do not turn context variables into expression
        // source. Unknown return propagation remains explicitly uncertain.
        if(fallback.input()){fallback.safeFlow=false;fallback.safeSql=fallback.scalar;}
        if(!targets.isEmpty()&&targets.stream().allMatch(t->!t.body)){if(fallback.input())fallback.uncertain=true;}else if(targets.isEmpty()&&fallback.input()){unknownSites.add(e.method.path+":"+c.getBegin());fallback.uncertain=true;}
        return fallback.step(site(e.method,c,"propagation","return through "+(owner.isBlank()?"unresolved receiver":owner)+"."+name));
    }
    private void execution(MethodCallExpr c,Fact value,Env e,String kind){if(value.input()&&value.constant==null)e.sink(new Sink(kind.equals("command")?"command":"script",site(e.method,c,"execution",kind.equals("command")?"input controls process execution":"input controls evaluated script/expression text"),value,List.of()));else if(e.guard.input()&&value.constant!=null)e.sink(new Sink("guarded-"+kind,site(e.method,c,"execution","fixed privileged action has an input-controlled branch trigger"),e.guard,List.of()));}
    private static Fact command(List<Fact> args){if(args.isEmpty())return new Fact();Fact first=args.getFirst();String exe=first.constant;if(args.size()==1){if(exe!=null)return first;int end=-1;for(int i=0;i<first.prefix.length();i++)if(Character.isWhitespace(first.prefix.charAt(i))){end=i;break;}if(end<1)return first;exe=first.prefix.substring(0,end);}else if(exe==null)return first;String base=exe.replace('\\','/');base=base.substring(base.lastIndexOf('/')+1).toLowerCase(Locale.ROOT);boolean shell=Set.of("sh","bash","dash","zsh","cmd","cmd.exe","powershell","powershell.exe","pwsh","python","python3","node","perl","ruby").contains(base);if(shell)return combine(args);return new Fact();}
    private void xmlSinks(Method mapper,List<Fact> args,MethodCallExpr call,Env e){for(var slot:resources.sql.getOrDefault(mapper.owner.name+"#"+mapper.node.getNameAsString(),List.of())){
        String expression=slot.expression();String root=expression.split("[.\\[(]",2)[0];int index=-1;
        for(int i=0;i<mapper.node.getParameters().size();i++){var parameter=mapper.node.getParameter(i);String alias=parameter.getNameAsString();for(var a:parameter.getAnnotations())if(a.getNameAsString().equals("Param")||a.getNameAsString().endsWith(".Param")){if(a instanceof SingleMemberAnnotationExpr s&&s.getMemberValue() instanceof StringLiteralExpr literal)alias=literal.asString();}if(root.equals(alias)||root.equals("param"+(i+1))||root.equals("arg"+i))index=i;}
        boolean implicitProperty=index<0&&args.size()==1;if(implicitProperty)index=0;if(index<0||index>=args.size()){project.diagnostics.putIfAbsent("sql-slot:"+slot.location(),new Models.Diagnostic("JAVA_SQL_BINDING_UNRESOLVED",slot.location().path(),slot.location().line(),1,"raw SQL substitution could not be bound to a mapper parameter"));continue;}Fact value=args.get(index);
        boolean wrapperSlot=root.equals("ew")||expression.contains("getCustomSqlSegment")||expression.contains("customSqlSegment")||expression.contains("sqlSegment");
        if(wrapperSlot){if(!value.rawSql&&!value.input())continue;}
        else if(expression.contains(".")||implicitProperty){String field=expression.contains(".")?expression.substring(expression.indexOf('.')+1).split("[.(]",2)[0]:root;var owner=project.types.get(project.qualify(value.type,e.method.owner));var info=project.field(owner,field);if(info!=null)value=value.type(project.qualifyType(info.type(),owner));}
        if(value.unsafeSql()||value.rawSql)e.sink(new Sink(wrapperSlot?"wrapper-sql":"java-sql-injection",slot.location(),value.step(site(e.method,call,"sql-execution","mapper call supplies a raw XML substitution")),List.of()));
    }}
    private void emit(Sink sink,boolean entry){String rule=sink.kind;Fact value=sink.value;
        if(rule.equals("wrapper-sql")){if(!value.rawSql)return;rule="java-sql-injection";}
        if(rule.equals(JACKSON)&&!value.broad)return;
        if(Set.of("command","script","guarded-command","guarded-script").contains(rule)){if(!value.web||rule.startsWith("guarded-")&&!enabled.contains(WEB_EXEC))return;rule=enabled.contains(WEB_EXEC)?WEB_EXEC:rule.equals("command")?"java-command-injection":"java-dynamic-code-execution";}
        else if(rule.equals("java-sql-injection")&&!value.web)return;
        else if(Set.of(CLASS_LOAD,AUTH_BYPASS).contains(rule)&&!value.web)return;
        else if(rule.equals(WEB_IMPLANT)&&!value.web&&!value.loaded&&!value.broad){/* a proven dangerous handler is still a review candidate */}
        if(!enabled.contains(rule))return;
        var evidence=new LinkedHashMap<String,Object>();evidence.put("ruleFamily",rule);evidence.put("securityModelVersion",VERSION);evidence.put("certainty",rule.equals(JACKSON)||rule.equals(JWT)?"configuration-risk":"possible");evidence.put("entryVerified",entry);evidence.put("unmodeledPropagation",value.uncertain);evidence.put("maliciousIntentProven",false);
        Fact located=value.step(sink.site);evidence.put("securityTrace",located.trace.stream().map(SecurityResources.Location::evidence).toList());if(!sink.related.isEmpty())evidence.put("relatedLocations",sink.related.stream().map(SecurityResources.Location::evidence).toList());
        if(rule.equals(JACKSON))evidence.put("missingProofs",List.of("attacker control of serialized bytes","reachable allowed object types","effective deployment configuration"));if(rule.equals(JWT)){evidence.put("redactSnippet",true);evidence.put("secretValue","[REDACTED]");evidence.put("runtimeOverride","unknown");}
        String message=switch(rule){case "java-command-injection"->"外部输入控制进程命令或解释器参数；需复核输入约束和运行权限";case "java-dynamic-code-execution"->"外部输入进入脚本或表达式文本并被执行；需复核执行上下文";case WEB_EXEC->"请求输入或特殊输入分支控制危险执行；属于可疑远控能力，尚未证明后门意图";case CLASS_LOAD->"不可信输入字节进入动态类定义；需复核载荷来源、执行可达性及插件信任边界";case WEB_IMPLANT->"Web 组件注册与不可信加载、危险处理器或输入触发条件关联；需复核运行阶段和合法用途";case AUTH_BYPASS->"特殊输入分支绕过可见的普通凭据校验并返回认证成功或建立身份";case JACKSON->"宽泛 Jackson 多态配置进入解码或 Redis codec 使用路径；尚未证明可利用反序列化链";case JWT->"源码设置固定 JWT 签名密钥；值已脱敏，需复核有效配置";default->"外部输入进入原始 SQL 文本，未在该路径证明参数绑定、类型约束或有效净化";};add(rule,sink.site,message,evidence);
    }
    private void add(String rule,SecurityResources.Location site,String message,Map<String,Object> evidence){String key=rule+":"+site.path()+":"+site.line()+":"+site.column();if(findings.size()>=10000){truncated=true;return;}var metadata=RuleCatalog.rule(rule);findings.putIfAbsent(key,new Models.Finding(rule,metadata.severity(),metadata.cwe(),site.path(),site.line(),site.column(),metadata.title(),message,evidence));}
    private static SecurityResources.Location site(Method m,Node n,String kind,String message){return new SecurityResources.Location(m.path,n.getBegin().map(p->p.line).orElse(1),n.getBegin().map(p->p.column).orElse(1),kind,message);}
    private boolean entry(MethodDeclaration method,TypeDeclaration<?> type,ProjectContext.TypeInfo owner){return method.getAnnotations().stream().anyMatch(a->Set.of("org.springframework.web.bind.annotation.RequestMapping","org.springframework.web.bind.annotation.GetMapping","org.springframework.web.bind.annotation.PostMapping","org.springframework.web.bind.annotation.PutMapping","org.springframework.web.bind.annotation.DeleteMapping","org.springframework.web.bind.annotation.PatchMapping").contains(project.qualify(a.getNameAsString(),owner)))
        ||Set.of("doGet","doPost","doPut","doDelete","service","doFilter","handleRequest").contains(method.getNameAsString())&&method.getParameters().stream().anyMatch(p->requestType(project.qualify(p.getTypeAsString(),owner)));}
    private boolean boundParameter(Parameter p,Method m){String type=project.qualify(p.getTypeAsString(),m.owner);return !Set.of("jakarta.servlet.http.HttpServletResponse","javax.servlet.http.HttpServletResponse","org.springframework.ui.Model","org.springframework.validation.BindingResult","org.springframework.validation.Errors").contains(type);}
    private boolean requestType(String type){return Set.of("jakarta.servlet.http.HttpServletRequest","javax.servlet.http.HttpServletRequest","jakarta.servlet.ServletRequest","javax.servlet.ServletRequest","org.springframework.http.HttpEntity","org.springframework.http.RequestEntity","io.undertow.server.HttpServerExchange").contains(ProjectContext.erase(type));}
    private boolean classDefiner(String owner,ProjectContext.TypeInfo scope){return owner.equals("java.lang.ClassLoader")||project.inherits(owner,"java.lang.ClassLoader",scope)||Set.of("java.lang.invoke.MethodHandles.Lookup","sun.misc.Unsafe","jdk.internal.misc.Unsafe").contains(owner);}
    private boolean registration(String owner,String name,ProjectContext.TypeInfo scope){return (owner.equals("org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping")||project.inherits(owner,"org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping",scope))&&name.equals("registerMapping")
        ||(owner.equals("org.springframework.web.servlet.handler.AbstractHandlerMapping")||project.inherits(owner,"org.springframework.web.servlet.handler.AbstractHandlerMapping",scope))&&name.equals("setInterceptors")
        ||owner.equals("org.springframework.web.servlet.config.annotation.InterceptorRegistry")&&name.equals("addInterceptor")
        ||Set.of("jakarta.servlet.ServletContext","javax.servlet.ServletContext","io.undertow.servlet.api.DeploymentInfo","io.undertow.servlet.core.ManagedFilters","io.undertow.servlet.core.ManagedServlets").contains(owner)&&Set.of("addFilter","addServlet","addListener","addFilterUrlMapping","insertFilterUrlMapping").contains(name)
        ||owner.startsWith("io.undertow.")&&Set.of("addInitialHandlerChainWrapper","addOuterHandlerChainWrapper","setHandler").contains(name);}
    private boolean dangerousHandler(String type){return methods.values().stream().filter(m->m.owner.name.equals(ProjectContext.erase(type))).map(m->summary(m.key)).filter(Objects::nonNull).anyMatch(s->s.sinks.stream().anyMatch(x->Set.of("command","script","guarded-command","guarded-script",CLASS_LOAD).contains(x.kind)));}
    private void applyGuards(Expression x,boolean truth,Env env){for(var binding:guardedVariables(x,truth,env).entrySet()){Fact value=env.locals.get(binding.getKey());if(value!=null){value=value.copy();value.safeSql=true;if(binding.getValue()!=null)value.constant=binding.getValue();env.locals.put(binding.getKey(),value.step(site(env.method,x,"validation","successful branch constrains the SQL identifier or selects a fixed value")));}}}
    private Map<String,String> guardedVariables(Expression x,boolean truth,Env env){
        if(x instanceof EnclosedExpr e)return guardedVariables(e.getInner(),truth,env);if(x instanceof UnaryExpr u&&u.getOperator()==UnaryExpr.Operator.LOGICAL_COMPLEMENT)return guardedVariables(u.getExpression(),!truth,env);
        if(x instanceof BinaryExpr b&&(b.getOperator()==BinaryExpr.Operator.AND||b.getOperator()==BinaryExpr.Operator.OR)){var a=new LinkedHashMap<>(guardedVariables(b.getLeft(),truth,env));var right=guardedVariables(b.getRight(),truth,env);boolean both=b.getOperator()==BinaryExpr.Operator.AND?truth:!truth;if(both)a.putAll(right);else a.entrySet().removeIf(v->!right.containsKey(v.getKey()));return a;}
        if(!truth)return Map.of();
        if(x instanceof MethodCallExpr c){
            if(c.getNameAsString().equals("matches")&&c.getScope().orElse(null) instanceof NameExpr name&&c.getArguments().size()==1&&c.getArgument(0) instanceof StringLiteralExpr pattern&&safeIdentifierPattern(pattern.asString())){var m=new LinkedHashMap<String,String>();m.put(name.getNameAsString(),null);return m;}
            if(c.getNameAsString().equals("equals")&&c.getArguments().size()==1){Expression a=c.getScope().orElse(null),b=c.getArgument(0);if(a instanceof NameExpr name&&b instanceof StringLiteralExpr fixed)return Map.of(name.getNameAsString(),fixed.asString());if(b instanceof NameExpr name&&a instanceof StringLiteralExpr fixed)return Map.of(name.getNameAsString(),fixed.asString());}
            if(c.getNameAsString().equals("contains")&&c.getArguments().size()==1&&c.getArgument(0) instanceof NameExpr variable&&c.getScope().isPresent()){Fact collection=eval(c.getScope().get(),env);if(!collection.elements.isEmpty()&&collection.elements.stream().allMatch(f->f.constant!=null&&f.constant.matches("[a-zA-Z_][a-zA-Z0-9_.]*"))){var m=new LinkedHashMap<String,String>();m.put(variable.getNameAsString(),null);return m;}}
            Fact receiver=c.getScope().map(s->eval(s,env)).orElseGet(()->new Fact(env.method.owner.name));List<Fact> args=c.getArguments().stream().map(v->eval(v,env)).toList();
            for(var target:targets(env.method.owner,receiver,c,args)){var method=methods.get(target.key);if(method==null||method.node.getBody().isEmpty())continue;var statements=method.node.getBody().get().getStatements();if(statements.size()!=1||!(statements.get(0) instanceof ReturnStmt r)||r.getExpression().isEmpty()||!(r.getExpression().get() instanceof MethodCallExpr check)||!check.getNameAsString().equals("matches")||!(check.getScope().orElse(null) instanceof NameExpr parameter)||check.getArguments().size()!=1||!(check.getArgument(0) instanceof StringLiteralExpr pattern)||!safeIdentifierPattern(pattern.asString()))continue;
                for(int i=0;i<method.node.getParameters().size()&&i<c.getArguments().size();i++)if(method.node.getParameter(i).getNameAsString().equals(parameter.getNameAsString())&&c.getArgument(i) instanceof NameExpr variable){var m=new LinkedHashMap<String,String>();m.put(variable.getNameAsString(),null);return m;}
            }
        }return Map.of();
    }
    private static boolean safeIdentifierPattern(String regex){if(regex==null)return false;String r=regex;if(r.startsWith("^"))r=r.substring(1);if(r.endsWith("$"))r=r.substring(0,r.length()-1);if(!r.startsWith("[")||!r.endsWith("]+"))return false;String body=r.substring(1,r.length()-2).replace("a-z","").replace("A-Z","").replace("0-9","").replace("\\.",".");return body.chars().allMatch(c->c>='a'&&c<='z'||c>='A'&&c<='Z'||c>='0'&&c<='9'||c=='_'||c=='.');}
    private boolean objectMapper(String owner,ProjectContext.TypeInfo scope){return owner.equals("com.fasterxml.jackson.databind.ObjectMapper")||owner.equals("com.fasterxml.jackson.databind.json.JsonMapper")||project.inherits(owner,"com.fasterxml.jackson.databind.ObjectMapper",scope);}
    private boolean wrapper(String owner,ProjectContext.TypeInfo scope){return owner.startsWith("com.baomidou.mybatisplus.core.conditions.")||project.inherits(owner,"com.baomidou.mybatisplus.core.conditions.Wrapper",scope);}
    private boolean mapper(String owner,ProjectContext.TypeInfo scope){return project.mapper(project.types.get(owner))||project.inherits(owner,"com.baomidou.mybatisplus.core.mapper.BaseMapper",scope);}
    private boolean mybatisService(String owner,ProjectContext.TypeInfo scope){return project.inherits(owner,"com.baomidou.mybatisplus.extension.service.IService",scope)||project.inherits(owner,"com.baomidou.mybatisplus.extension.service.impl.ServiceImpl",scope);}
    private static boolean queryMethod(String name){return name.startsWith("select")||Set.of("list","page","count","getOne","update","remove","exists").contains(name);}
    private static boolean authLogin(String owner,String name){return Set.of("cn.dev33.satoken.stp.StpUtil","cn.dev33.satoken.stp.StpLogic").contains(owner)&&name.equals("login")||owner.equals("org.springframework.security.core.context.SecurityContext")&&name.equals("setAuthentication");}
    private boolean credentialVerifier(MethodCallExpr c,ProjectContext.TypeInfo scope){String rendered=c.getScope().map(Object::toString).orElse("");String owner=project.qualify(rendered,scope);String declared=c.getScope().map(x->ExpressionFacts.declaredType(x,c)).orElse("");if(declared.isEmpty()){var field=project.field(scope,rendered);if(field!=null)declared=field.type();}String receiver=project.qualify(declared,scope);return (owner.equals("cn.hutool.crypto.digest.BCrypt")||owner.equals("org.mindrot.jbcrypt.BCrypt"))&&Set.of("checkpw","verify").contains(c.getNameAsString())||(receiver.equals("org.springframework.security.crypto.password.PasswordEncoder")||project.inherits(receiver,"org.springframework.security.crypto.password.PasswordEncoder",scope))&&c.getNameAsString().equals("matches");}
    private boolean credentialVerifierExpr(Expression x,ProjectContext.TypeInfo owner){if(x instanceof EnclosedExpr e)return credentialVerifierExpr(e.getInner(),owner);return x instanceof MethodCallExpr c&&credentialVerifier(c,owner);}
    private boolean negatedVerifier(Expression x,ProjectContext.TypeInfo owner){if(x instanceof EnclosedExpr e)return negatedVerifier(e.getInner(),owner);return x instanceof UnaryExpr u&&u.getOperator()==UnaryExpr.Operator.LOGICAL_COMPLEMENT&&credentialVerifierExpr(u.getExpression(),owner);}
    private boolean requiresVerifier(Expression x,ProjectContext.TypeInfo owner){if(x instanceof EnclosedExpr e)return requiresVerifier(e.getInner(),owner);if(x instanceof BinaryExpr b){if(b.getOperator()==BinaryExpr.Operator.AND)return requiresVerifier(b.getLeft(),owner)||requiresVerifier(b.getRight(),owner);if(b.getOperator()==BinaryExpr.Operator.OR)return requiresVerifier(b.getLeft(),owner)&&requiresVerifier(b.getRight(),owner);}return credentialVerifierExpr(x,owner);}
    private Fact trigger(Expression x,Env e){if(x instanceof EnclosedExpr enclosed)return trigger(enclosed.getInner(),e);if(x instanceof BinaryExpr b){if(b.getOperator()==BinaryExpr.Operator.AND||b.getOperator()==BinaryExpr.Operator.OR)return merge(trigger(b.getLeft(),e),trigger(b.getRight(),e));if(b.getOperator()==BinaryExpr.Operator.EQUALS){var a=eval(b.getLeft(),e);var right=eval(b.getRight(),e);if(a.constant!=null&&right.input()||right.constant!=null&&a.input())return combine(List.of(a,right)).step(site(e.method,b,"trigger","input is compared with a fixed branch trigger; literal redacted"));}}
        if(x instanceof MethodCallExpr c&&Set.of("equals","equalsIgnoreCase").contains(c.getNameAsString())){var facts=new ArrayList<Fact>();c.getScope().ifPresent(s->facts.add(eval(s,e)));c.getArguments().forEach(a->facts.add(eval(a,e)));if(facts.stream().anyMatch(f->f.constant!=null)&&facts.stream().anyMatch(Fact::input))return combine(facts).step(site(e.method,c,"trigger","input is compared with a fixed branch trigger; literal redacted"));}return new Fact();}
    private List<ProjectContext.MethodInfo> targets(ProjectContext.TypeInfo caller,Fact receiver,MethodCallExpr call,List<Fact> arguments){var values=arguments.stream().map(f->new NullDereferenceAnalyzer.Value(SourceParsing.type(f.type),NullDereferenceAnalyzer.Nullness.UNKNOWN)).toList();return project.targets(caller,receiver.type,call,values);}
    private String resultType(List<ProjectContext.MethodInfo> targets,ProjectContext.TypeInfo scope,Fact receiver,List<Fact> args){var values=args.stream().map(this::typedValue).toList();var results=targets.stream().map(t->project.specializedReturn(t,values,scope,receiver.type)).distinct().toList();return results.size()==1?results.getFirst():"";}
    private NullDereferenceAnalyzer.Value typedValue(Fact fact){String type=fact.type;if(type.equals("java.lang.Class")&&fact.constant!=null&&!fact.constant.contains("#"))type="java.lang.Class<"+fact.constant+">";return new NullDereferenceAnalyzer.Value(SourceParsing.type(type),NullDereferenceAnalyzer.Nullness.UNKNOWN);}
    private String getterType(Fact receiver,String name,ProjectContext.TypeInfo scope){var type=project.types.get(project.qualify(receiver.type,scope));String field=name.length()>3?Character.toLowerCase(name.charAt(3))+name.substring(4):"";var info=project.field(type,field);return info==null?"":project.qualifyType(info.type(),type);}
    private final Map<String,String> platformReturns=new HashMap<>();
    private String platformResult(String owner,String name,int arity){if(!owner.startsWith("java.")&&!owner.startsWith("javax.crypto.")&&!owner.startsWith("javax.script."))return "";String key=owner+"#"+name+":"+arity;if(platformReturns.containsKey(key))return platformReturns.get(key);String result="";try{var type=Class.forName(owner,false,ClassLoader.getPlatformClassLoader());var results=Arrays.stream(type.getMethods()).filter(m->m.getName().equals(name)&&(m.getParameterCount()==arity||m.isVarArgs()&&arity>=m.getParameterCount()-1)).map(m->m.getReturnType().getCanonicalName()).distinct().toList();if(results.size()==1)result=results.getFirst();}catch(ClassNotFoundException|LinkageError ignored){}if(platformReturns.size()<4096)platformReturns.put(key,result);return result;}
    private static boolean scalarType(String type){return Set.of("boolean","byte","short","int","long","float","double","java.lang.Boolean","java.lang.Byte","java.lang.Short","java.lang.Integer","java.lang.Long","java.lang.Float","java.lang.Double","java.math.BigDecimal","java.math.BigInteger").contains(type);}
}
