package com.binaryscan.checker.java;

import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;
import java.nio.charset.StandardCharsets;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

final class ProjectAnalysisTest {
    private static final List<String> RULES = List.of("java-null-dereference");
    private Models.CheckResponse analyze(List<Models.SourceFile> sources) {
        try (var fixture = new Fixture()) { return fixture.analyze(sources); }
    }
    private static final class Fixture implements AutoCloseable {
        final ProjectCheckController controller = new ProjectCheckController(new JavaAnalyzer());
        String create(List<Models.SourceFile> sources) {
            var files = sources.stream().map(s -> new Models.ProjectFile(s.path(),
                ProjectCheckController.sha256(s.content().getBytes(StandardCharsets.UTF_8)), s.content().getBytes(StandardCharsets.UTF_8).length)).toList();
            return controller.create(new Models.ProjectRequest("java-project-v1", "project", "run", "a".repeat(64),
                RuleCatalog.VERSION, RULES, files)).sessionId();
        }
        Models.CheckResponse analyze(List<Models.SourceFile> sources) {
            String id = create(sources);
            for (int start = 0; start < sources.size(); start += 200)
                controller.upload(id, new Models.ProjectUpload(sources.subList(start, Math.min(start + 200, sources.size()))));
            return controller.analyze(id);
        }
        public void close() { controller.close(); }
    }
    private Models.SourceFile source(String path, String code) { return new Models.SourceFile(path, code); }

    @Test void parsesJava21AndReportsRealSyntaxFailureWithCoverage() {
        var result = analyze(List.of(source("Good.java", "class Good { int f(Object o) { return o instanceof String s ? s.length() : 0; } }"),
            source("Bad.java", "class Bad { void f( }")));
        assertEquals(2, result.coverage().totalFiles()); assertEquals(1, result.coverage().parsedFiles());
        assertEquals(1, result.coverage().failedFiles()); assertEquals("partial", result.status());
        assertEquals("JAVA_PARSE_ERROR", result.diagnosticDetails().getFirst().code());
        assertFalse(result.diagnosticDetails().getFirst().message().contains("parser rejected"));
    }
    @Test void propagatesReturnAndParameterNullnessAcrossFilesWithNavigableTrace() {
        var result = analyze(List.of(
            source("A.java", "package p; class A { B b; String load(){return b.find();} int size(){return load().length();} void run(){b.consume(null);} }"),
            source("B.java", "package p; class B { String find(){return null;} void consume(String s){s.length();} }")));
        assertTrue(result.findings().stream().anyMatch(f -> f.path().equals("A.java")), result.toString());
        assertTrue(result.findings().stream().anyMatch(f -> f.path().equals("B.java")), result.toString());
        var trace = (List<?>) result.findings().getFirst().evidence().get("nullnessTrace");
        assertTrue(trace.size() >= 3, trace.toString());
        assertTrue(trace.stream().allMatch(s -> ((Map<?,?>)s).get("path").equals("A.java") || ((Map<?,?>)s).get("path").equals("B.java")));
    }
    @Test void keepsContextAcrossMoreThanTwoHundredUploadedFiles() {
        var sources = new ArrayList<Models.SourceFile>();
        sources.add(source("A.java", "class A { Z z; int f(){return z.value().length();} }"));
        for (int index = 0; index < 200; index++) sources.add(source("F"+index+".java", "class F"+index+" {}"));
        sources.add(source("Z.java", "class Z { String value(){return null;} }"));
        var result = analyze(sources);
        assertEquals(202, result.coverage().parsedFiles()); assertEquals(1, result.findings().size(), result.toString());
    }
    @Test void modelsMyBatisSingleResultsAndMapGetButNotAnUnrelatedMethodName() {
        var result = analyze(List.of(
            source("Row.java", "package p; class Row { String code(){return \"x\";} }"),
            source("Orders.java", "package p; import com.baomidou.mybatisplus.core.mapper.BaseMapper; interface Orders extends BaseMapper<Row> { Row custom(String id); }"),
            source("Other.java", "package p; interface Other { Row selectById(String id); }"),
            source("Use.java", "package p; import java.util.Map; class Use { Orders orders; Other other; Map<String,String> labels; int one(){return orders.selectById(1).code().length();} int custom(){return orders.custom(\"x\").code().length();} int lookup(){return labels.get(\"x\").length();} int unknown(){return other.selectById(\"x\").code().length();} }")));
        assertEquals(3, result.findings().size(), result.toString());
        assertTrue(result.findings().stream().allMatch(f -> f.evidence().get("nullnessCertainty").equals("possible")));
    }
    @Test void respectsNullGuardsAndAssertionContractsWithoutGuessingJavaAssertEnabled() {
        var result = analyze(List.of(source("Guard.java", """
            import java.util.Map;
            import org.springframework.util.Assert;
            class Guard {
              Map<String,String> map;
              int checked(){String s=map.get("x"); if(s==null)return 0; return s.length();}
              int asserted(){String s=map.get("x"); Assert.notNull(s,"missing"); return s.length();}
              int languageAssert(){String s=map.get("x"); assert s!=null; return s.length();}
            }
            """)));
        assertEquals(1, result.findings().size(), result.toString());
        assertEquals(7, result.findings().getFirst().line());
    }
    @Test void analyzesLoopsTryAndLambdaBodies() {
        var result = analyze(List.of(source("Flows.java", """
            class Flows {
              void loops(boolean b){while(b){String s=null;s.length();}}
              void tried(){try{String s=null;s.length();}catch(Exception e){}}
              void closure(){Runnable r=()->{String s=null;s.length();};}
            }
            """)));
        assertEquals(3, result.findings().size(), result.toString());
    }
    @Test void rejectsManifestMismatchIncompleteUploadAndDoesNotLeakAcrossSessions() {
        try (var fixture = new Fixture()) {
            var source = source("Demo.java", "class Demo {} 中文");
            String id = fixture.create(List.of(source));
            assertEquals(409, assertThrows(ResponseStatusException.class, () -> fixture.controller.analyze(id)).getStatusCode().value());
            assertEquals(400, assertThrows(ResponseStatusException.class, () -> fixture.controller.upload(id,
                new Models.ProjectUpload(List.of(source("Demo.java", "class Demo {}"))))).getStatusCode().value());
            fixture.controller.upload(id, new Models.ProjectUpload(List.of(source)));
            fixture.controller.upload(id, new Models.ProjectUpload(List.of(source)));
            fixture.controller.delete(id);
            assertEquals(404, assertThrows(ResponseStatusException.class, () -> fixture.controller.analyze(id)).getStatusCode().value());
            assertEquals(0, fixture.analyze(List.of(source("Safe.java", "class Safe {int size(String x){return x.length();}}"))).findings().size());
        }
    }
    @Test void unresolvedLibraryCallsAreCoverageCountersRatherThanExecutionFailures() {
        var result = analyze(List.of(source("External.java", "class External { vendor.Library library; void f(){library.run();} }")));
        assertEquals("complete", result.status()); assertTrue(result.coverage().unresolvedCalls() > 0);
    }
    @Test void doesNotProveOpenVirtualDispatchNonNullFromOneKnownImplementation() {
        var result = analyze(List.of(source("Virtual.java", """
            interface Value {String value();}
            class Known implements Value {public String value(){return "safe";}}
            class Use {Value value; int f(){String result=value.value(); if(result==null)return result.length();return 0;}}
            """)));
        assertEquals(1, result.findings().size(), result.toString());
    }
    @Test void boundsLongOrRecursiveCallChainsAndRetainsBranchEvidence() {
        var sources = new ArrayList<Models.SourceFile>();
        for (int i = 0; i < 20; i++) sources.add(source(String.format("%02d.java", i), "class C"+i+" { String value(){return "+
            (i == 19 ? "null" : "new C"+(i+1)+"().value()")+";} }"));
        var result = analyze(sources);
        assertTrue(result.diagnosticDetails().stream().anyMatch(d -> d.code().equals("JAVA_FIXED_POINT_LIMIT")), result.toString());
        var branch = analyze(List.of(source("Branch.java", "class Branch {String f(boolean b){String s=null;if(b)s=\"safe\";return s;} int size(boolean b){return f(b).length();}}")));
        assertEquals(1, branch.findings().size(), branch.toString());
        assertTrue(((List<?>)branch.findings().getFirst().evidence().get("nullnessTrace")).size() >= 3);
    }
    @Test void tracksFieldAssignmentsUnboxingAndModernSwitchValues() {
        var result = analyze(List.of(source("Modern.java", """
            class Modern {
              String field;
              void assigned(){this.field=null;this.field.length();}
              int boxed(){Integer value=null; return value;}
              int switched(int n){String value=switch(n){case 0 -> null;default -> {yield "safe";}};return value.length();}
              int guardedSwitch(int n){String value=null;switch(n){default:value="safe";}return value.length();}
            }
            """)));
        assertEquals(3, result.findings().size(), result.toString());
        assertTrue(result.findings().stream().anyMatch(f -> f.evidence().get("dereferenceKind").equals("unboxing")));
    }
    @Test void honorsKnownNullableContractsAndDoesNotBindAnonymousMethodsToOuterMethods() {
        var result = analyze(List.of(source("Contracts.java", """
            import org.jetbrains.annotations.Nullable;
            class Contracts {
              @Nullable String external(){return vendor.Library.load();}
              int caller(){return external().length();}
              int nullableParameter(@Nullable String s){return s.length();}
              String safe(){return "safe";}
              Object object=new Object(){String safe(){return null;}};
              int safeCaller(){return safe().length();}
            }
            """)));
        assertEquals(2, result.findings().size(), result.toString());
        assertEquals(result.coverage().totalMethods(), result.coverage().analyzedMethods());
    }
    @Test void preservesWritesAtIntermediateAndFinalExceptionEntrances() {
        var result = analyze(List.of(source("CatchFlow.java", """
            class CatchFlow {
              void finalThrow(){String s="safe";try{s=null;throw new RuntimeException();}catch(RuntimeException e){s.length();}}
              void intermediate(boolean flag){String s="safe";try{s=null;if(flag)throw new RuntimeException();s="safe";}catch(RuntimeException e){s.length();}}
              void external(){String s="safe";try{s=null;vendor.Library.run();s="safe";}catch(RuntimeException e){s.length();}}
              void guarded(){String s="safe";try{s=null;throw new RuntimeException();}catch(RuntimeException e){if(s!=null)s.length();}}
              void impossibleCatch(){String s="safe";try{s=null;s="safe";}catch(RuntimeException e){s.length();}}
            }
            """)));
        assertEquals(3, result.findings().size(), result.toString());
        assertEquals(Set.of(2,3,4), result.findings().stream().map(Models.Finding::line).collect(java.util.stream.Collectors.toSet()));
    }
    @Test void includesForUpdatesInFixedPointAndRoutesContinueButNotBreakThroughUpdate() {
        var result = analyze(List.of(source("ForFlow.java", """
            class ForFlow {
              void update(){String s="safe";for(;;s=null){s.length();}}
              void continued(boolean flag){String s="safe";for(;;s=null){if(flag)continue;s.length();}}
              void broken(){String s="safe";for(;;s=null){s.length();break;}s.length();}
              void returned(){String s="safe";for(;;s=null){s.length();return;}}
            }
            """)));
        assertEquals(2, result.findings().size(), result.toString());
        assertEquals(Set.of(2,3), result.findings().stream().map(Models.Finding::line).collect(java.util.stream.Collectors.toSet()));
    }
    @Test void distinguishesStaticAndInheritedStaticFieldsFromInstanceDereferences() {
        var result = analyze(List.of(source("StaticFields.java", """
            class Parent {static int inherited=1;}
            class StaticFields extends Parent {
              static int value=1; int member=1;
              int allowed(){StaticFields receiver=null;return receiver.value+receiver.inherited;}
              int invalid(){StaticFields receiver=null;return receiver.member;}
            }
            """)));
        assertEquals(1, result.findings().size(), result.toString()); assertEquals(5, result.findings().getFirst().line());
    }
    @Test void excludesDuplicateTypeBodiesFromSharedMethodSummaries() {
        var result = analyze(List.of(source("first/Duplicate.java", "package p; class Duplicate {static String value(){return null;}}"),
            source("second/Duplicate.java", "package p; class Duplicate {static String value(){return \"safe\";}}"),
            source("Use.java", "package p; class Use {int f(){String s=Duplicate.value();if(s==null)return s.length();return 0;}}")));
        assertEquals("partial", result.status());
        assertTrue(result.diagnosticDetails().stream().anyMatch(d -> d.code().equals("JAVA_DUPLICATE_TYPE")));
        assertEquals(1, result.findings().size(), result.toString());
    }
}
