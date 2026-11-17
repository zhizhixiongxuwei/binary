package com.binaryscan.checker.java;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

final class GenericContextTest {
    @TempDir Path root;
    Models.CheckResponse check(String mapperBody,boolean ambiguous)throws Exception{
        var source="""
            import io.github.linpeilie.Converter;
            import io.github.linpeilie.BaseMapper;
            class Source {}
            class Target {int size(){return 1;}}
            interface Mapping extends BaseMapper<Source,Target> {}
            class MappingImpl implements Mapping {public Target convert(Source source){%s}}
            %s
            class Use {
              static Converter converter;
              static <S,T> T convert(S source,Class<T> type){if(source==null)return null;return converter.convert(source,type);}
              int safe(){return convert(new Source(),Target.class).size();}
              int nullInput(){return Use.<Source,Target>convert(null,Target.class).size();}
            }
            """.formatted(mapperBody,ambiguous?"class OtherMappingImpl implements Mapping {public Target convert(Source source){return null;}}":"");
        var file=root.resolve("Use.java");Files.writeString(file,source);
        return ProjectAnalyzer.analyze("generic",List.of(new ProjectAnalyzer.Input("Use.java",file)),List.of("java-null-dereference"),new JavaAnalyzer(),new FrameworkContracts(Map.of("io.github.linpeilie:mapstruct-plus","1.3.6")));
    }
    @Test void genericSpecializationNeedsConcreteMapperProofAndRetainsNullInput()throws Exception{
        var r=check("if(source==null)return null;return new Target();",false);
        assertEquals(1,r.findings().size(),r.toString());assertEquals(12,r.findings().getFirst().line());
        assertTrue(r.modelSummary().get("proofs").toString().contains("generated-mapper"),r.toString());
    }
    @Test void customNullMapperAndAmbiguousDispatchRemainVisible()throws Exception{
        assertEquals(2,check("return null;",false).findings().size());
        assertEquals(2,check("if(source==null)return null;return new Target();",true).findings().size());
    }
    @Test void dependencyGenericSignatureAndNullableAnnotationAffectSourceCalls()throws Exception{
        var context=new ProjectContext();String index="""
            {"version":"java-type-index-v1","inputSha256":"%s","classpathOrder":"unverified","types":[
             {"name":"vendor.Parent","parent":"java.lang.Object","interfaces":[],"signature":"<T:Ljava/lang/Object;>Ljava/lang/Object;","access":1,"module":"lib.jar","sha256":"%s","methods":[{"name":"find","descriptor":"()Ljava/lang/Object;","signature":"()TT;","access":1,"annotations":["org.jetbrains.annotations.Nullable"]}],"fields":[{"name":"value","descriptor":"Ljava/lang/Object;","signature":"TT;","access":1}]}
            ],"diagnostics":[]}
            """.formatted("a".repeat(64),"b".repeat(64));
        DependencyIndex.load(index,"a".repeat(64),context);
        DependencyIndex.load(index,"A".repeat(64),new ProjectContext());
        var unit=SourceParsing.parse("class Child extends vendor.Parent<String> {int read(){return find().length();}}");context.register("Child.java",unit);
        assertTrue(context.inherits("Child","vendor.Parent",context.types.get("Child")));
        assertEquals("java.lang.String",context.field(context.types.get("Child"),"value").type());
        for(int i=0;i<8;i++)new JavaAnalyzer().analyze(new Models.SourceFile("Child.java",unit.toString()),Set.of("java-null-dereference"),context);
        context.recording=true;var r=new JavaAnalyzer().analyze(new Models.SourceFile("Child.java",unit.toString()),Set.of("java-null-dereference"),context);
        assertEquals(1,r.findings().size(),r.toString());
    }
    @Test void changedDefinitionHashesStayAmbiguousAndMismatchedInputIsRejected()throws Exception{
        var c=new ProjectContext();String index="""
            {"version":"java-type-index-v1","inputSha256":"%s","types":[
            {"name":"dup.Type","parent":"java.lang.Object","interfaces":[],"access":1,"module":"a.jar","sha256":"%s"},
            {"name":"dup.Type","parent":"java.lang.Object","interfaces":[],"access":1,"module":"b.jar","sha256":"%s"}]}
            """.formatted("a".repeat(64),"b".repeat(64),"c".repeat(64));
        assertThrows(java.io.IOException.class,()->DependencyIndex.load(index,"f".repeat(64),new ProjectContext()));
        DependencyIndex.load(index,"a".repeat(64),c);assertTrue(c.ambiguousTypes.contains("dup.Type"));assertFalse(c.types.containsKey("dup.Type"));
    }
    @Test void uncheckedClassCastCannotAcquireAnotherMapperProof()throws Exception{
        var file=root.resolve("Cast.java");Files.writeString(file,"""
          import io.github.linpeilie.Converter;
          import io.github.linpeilie.BaseMapper;
          class Source {}
          class Target {int size(){return 1;}}
          class Other {}
          interface Mapping extends BaseMapper<Source,Target> {}
          class MappingImpl implements Mapping {public Target convert(Source source){return new Target();}}
          class Use {static Converter converter;int risk(){Class<Target> target=(Class)Other.class;return converter.convert(new Source(),target).size();}}
          """);
        var r=ProjectAnalyzer.analyze("cast",List.of(new ProjectAnalyzer.Input("Cast.java",file)),List.of("java-null-dereference"),new JavaAnalyzer(),new FrameworkContracts(Map.of("io.github.linpeilie:mapstruct-plus","1.3.6")));
        assertEquals(1,r.findings().size(),r.toString());assertTrue(r.modelSummary().get("proofs").toString().isEmpty()||!r.modelSummary().get("proofs").toString().contains("generated-mapper"));
    }
    @Test void genericRuntimeArgumentsCannotChangeTheCompiledOverload()throws Exception{
        var file=root.resolve("Overload.java");Files.writeString(file,"""
          import java.util.*;
          class Use {
           static String choose(Object source){return null;}
           static String choose(List<?> source){return "value";}
           static <S> String erased(S source){return choose(source);}
           static <S extends List<?>> String bounded(S source){return choose(source);}
           int risk(){return erased(new ArrayList<>()).length();}
           int safe(){return bounded(new ArrayList<>()).length();}
          }
          """);
        var r=ProjectAnalyzer.analyze("overload",List.of(new ProjectAnalyzer.Input("Overload.java",file)),List.of("java-null-dereference"),new JavaAnalyzer());
        assertEquals(1,r.findings().size(),r.toString());assertEquals(7,r.findings().getFirst().line());
    }
    @Test void overriddenListConversionDoesNotAcquireTheDefaultContainerContract()throws Exception{
        var file=root.resolve("ListOverride.java");Files.writeString(file,"""
          import java.util.*;
          import io.github.linpeilie.Converter;
          class Custom extends Converter {public <S,T> List<T> convert(List<S> source,Class<T> target){return null;}}
          class Use {Converter converter=new Custom();int risk(){Class target=String.class;return converter.convert(List.of("value"),target).size();}}
          """);
        var r=ProjectAnalyzer.analyze("override",List.of(new ProjectAnalyzer.Input("ListOverride.java",file)),List.of("java-null-dereference"),new JavaAnalyzer(),new FrameworkContracts(Map.of("io.github.linpeilie:mapstruct-plus","1.3.6")));
        assertEquals(1,r.findings().size(),r.toString());
    }
}
