package com.binaryscan.checker.java;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class ConditionalContextsTest {
 @TempDir Path root;
 Models.CheckResponse check(String source)throws Exception{
  Path file=root.resolve("Fixture.java");Files.writeString(file,source);
  return ProjectAnalyzer.analyze("conditions",List.of(new ProjectAnalyzer.Input("Fixture.java",file)),List.of("java-null-dereference"),new JavaAnalyzer(),new FrameworkContracts(Map.of("cn.dev33:sa-token-core","1.37.0","org.springframework:spring-webmvc","6.1.8")));
 }
 @Test void explicitSuccessfulValidationRespectsGroupsMutationAndUncheckedCalls()throws Exception{
  var r=check("""
   import jakarta.validation.Validator;
   import jakarta.validation.constraints.NotNull;
   import org.jetbrains.annotations.Nullable;
   interface Create {}
   class Bean {@Nullable @NotNull String name;@Nullable @NotNull(groups=Create.class) String code;}
   class Use {
    int safe(Validator validator,Bean bean){var errors=validator.validate(bean);if(!errors.isEmpty())throw new IllegalArgumentException();return bean.name.length();}
    int differentGroup(Validator validator,Bean bean){var errors=validator.validate(bean,Create.class);if(!errors.isEmpty())throw new IllegalArgumentException();return bean.name.length();}
    int changed(Validator validator,Bean bean){var errors=validator.validate(bean);bean.name=null;if(!errors.isEmpty())throw new IllegalArgumentException();return bean.name.length();}
    int internal(Bean bean){return bean.name.length();}
   }
   """);
  assertEquals(Set.of(8,9,10),r.findings().stream().map(Models.Finding::line).collect(java.util.stream.Collectors.toSet()),r.toString());
  assertTrue(r.modelSummary().get("proofs").toString().contains("conditional-property"));
 }
 @Test void sameRequestWriteReadDoesNotProveSessionUserAfterCheckLoginOrEscape()throws Exception{
  var r=check("""
   import cn.dev33.satoken.context.SaHolder;
   import cn.dev33.satoken.session.SaSession;
   class Use {
    int safe(){var storage=SaHolder.getStorage();storage.set("user","present");return storage.get("user").toString().length();}
    int missing(SaSession session){return session.get("user").toString().length();}
    int deleted(){var storage=SaHolder.getStorage();storage.set("user","present");storage.delete("user");return storage.get("user").toString().length();}
    int escaped(){var storage=SaHolder.getStorage();storage.set("user","present");vendor.Code.changeContext();return storage.get("user").toString().length();}
   }
   """);
  assertEquals(Set.of(5,6,7),r.findings().stream().map(Models.Finding::line).collect(java.util.stream.Collectors.toSet()),r.toString());
 }
 @Test void computeCallbackMustBeProvenNonNull()throws Exception{
  var r=check("""
   import java.util.*;
   class Use {
    int safe(){Map<String,String> m=new HashMap<>();m.computeIfAbsent("k",k->"present");return m.get("k").length();}
    int nullable(){Map<String,String> m=new HashMap<>();m.computeIfAbsent("k",k->null);return m.get("k").length();}
   }
   """);
  assertEquals(1,r.findings().size(),r.toString());assertEquals(4,r.findings().getFirst().line());
 }
 @Test void cascadeDoesNotMakeNullableChildNonNullAndAsyncLosesConditionalFacts()throws Exception{
  var r=check("""
   import jakarta.validation.Validator;
   import jakarta.validation.Valid;
   import jakarta.validation.constraints.NotNull;
   import org.jetbrains.annotations.Nullable;
   class Child {@Nullable @NotNull String name;}
   class Bean {@Nullable @Valid Child child;@Nullable @NotNull String name;}
   class Use {
    int cascade(Validator v,Bean bean){var errors=v.validate(bean);if(!errors.isEmpty())throw new IllegalArgumentException();return bean.child.name.length();}
    void async(Validator v,Bean bean){var errors=v.validate(bean);if(!errors.isEmpty())throw new IllegalArgumentException();new Thread(()->bean.name.length()).start();}
   }
   """);
  assertEquals(Set.of(8,9),r.findings().stream().map(Models.Finding::line).collect(java.util.stream.Collectors.toSet()),r.toString());
 }

 @Test void stableSummaryCacheInvalidatesWhenACalleeChanges()throws Exception{
  String source="class Use {String first(){return second();} String second(){return third();} String third(){return null;} int risk(){return first().length();} String stable(){return \"present\";}}";
  var unit=SourceParsing.parse(source);var cached=new ProjectContext();cached.register("Use.java",unit);var uncached=new ProjectContext();uncached.memoize=false;uncached.register("Use.java",unit);
  for(var context:List.of(cached,uncached)){
   for(int i=0;i<16;i++){context.changed=false;new JavaAnalyzer().analyze(new Models.SourceFile("Use.java",source),Set.of("java-null-dereference"),context);if(!context.changed)break;}
   context.recording=true;
  }
  var a=new JavaAnalyzer().analyze(new Models.SourceFile("Use.java",source),Set.of("java-null-dereference"),cached);
  var b=new JavaAnalyzer().analyze(new Models.SourceFile("Use.java",source),Set.of("java-null-dereference"),uncached);
  assertEquals(b.findings(),a.findings());assertEquals(1,a.findings().size());assertTrue(cached.cachedVariantSkips>0);
 }
 @Test void unexpectedEngineFailureIsExportableAndDoesNotEchoSensitiveMessages()throws Exception{
  Path file=root.resolve("Fault.java");Files.writeString(file,"class Fault {int value(){return 1;}}");
  var result=ProjectAnalyzer.analyze("fault",List.of(new ProjectAnalyzer.Input("Fault.java",file)),List.of("java-null-dereference"),new JavaAnalyzer(),new FrameworkContracts(Map.of()),p->{if(p.phase().equals("analyzing"))throw new IllegalStateException("fixture-sensitive-value");});
  assertEquals("partial",result.status());assertTrue(result.diagnosticDetails().stream().anyMatch(d->d.code().equals("JAVA_ANALYZER_INTERNAL_ERROR")));assertFalse(result.toString().contains("fixture-sensitive-value"));
 }
 @Test void privateFactoryCacheNeedsOneMonitorAndNoEscapeOrInterveningCall()throws Exception{
  var r=check("""
   import java.util.*;
   class Locked {private static final Map<String,String> C=new HashMap<>();static synchronized String get(String k){C.put(k,"value");return C.get(k);}static synchronized void clear(){C.clear();}}
   class Open {public static final Map<String,String> C=new HashMap<>();static synchronized String get(String k){C.put(k,"value");return C.get(k);}}
   class Leaked {private static final Map<String,String> C=new HashMap<>();static synchronized Map<String,String> expose(){return C;}static synchronized String get(String k){C.put(k,"value");return C.get(k);}}
   class Reentrant {private static final Map<String,String> C=new HashMap<>();static synchronized String get(String k){C.put(k,"value");clear();return C.get(k);}static synchronized void clear(){C.clear();}}
   class Use {
    int safe(){return Locked.get("k").length();}
    int open(){return Open.get("k").length();}
    int leaked(){return Leaked.get("k").length();}
    int changed(){return Reentrant.get("k").length();}
   }
   """);
  assertEquals(Set.of(8,9,10),r.findings().stream().map(Models.Finding::line).collect(java.util.stream.Collectors.toSet()),r.toString());
  assertTrue(r.modelSummary().get("proofs").toString().contains("private-cache-monitor"));
 }
 @Test void reflectionPreventsPrivateCacheOwnershipAssumptions()throws Exception{
  var r=check("""
   import java.util.*;
   class Factory {private static final Map<String,String> C=new HashMap<>();static synchronized String get(String k){C.put(k,"value");return C.get(k);}static Object expose()throws Exception{return Factory.class.getDeclaredField("C").get(null);}}
   class Use {int risk(){return Factory.get("k").length();}}
   """);
  assertEquals(1,r.findings().size(),r.toString());
 }
 @Test void callbackCannotLeaveOtherPrivateCacheEntriesProvenPresent()throws Exception{
  var r=check("""
   import java.util.*;
   class Factory {
    private static final Map<String,String> A=new HashMap<>(),B=new HashMap<>();
    static synchronized String get(){B.put("k","value");A.computeIfAbsent("x",k->mutate());return B.get("k");}
    static synchronized String mutate(){B.clear();return "value";}
   }
   class Use {int risk(){return Factory.get().length();}}
   """);
  assertEquals(1,r.findings().size(),r.toString());
 }
}
