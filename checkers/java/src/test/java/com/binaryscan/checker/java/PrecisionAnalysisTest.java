package com.binaryscan.checker.java;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

final class PrecisionAnalysisTest {
    @TempDir Path root;
    private Models.CheckResponse analyze(String code) throws Exception { return analyze(code, Map.of("cn.hutool:hutool-core","5.8.27")); }
    private Models.CheckResponse analyze(String code, Map<String,String> frameworks) throws Exception {
        Path file=Files.createTempFile(root,"precision-",".java"); Files.writeString(file,code);
        return ProjectAnalyzer.analyze("precision",List.of(new ProjectAnalyzer.Input(file.getFileName().toString(),file)),
            List.of("java-null-dereference"),new JavaAnalyzer(),new FrameworkContracts(frameworks));
    }
    @Test void rejectsBeanToMapAndPageToListOverloadEdgesAndTypesClassLiterals() throws Exception {
        var result=analyze("""
            import java.util.*;
            class Base implements java.io.Serializable {}
            class Bean extends Base {int size(){return 1;}}
            interface IPage {}
            class Page implements IPage {}
            class Use {
              static <T> T convert(T source,Class<T> type){return source;}
              static <T> T convert(Map<String,Object> source,Class<T> type){return null;}
              static <T> List<T> convert(List<?> source,Class<T> type){return null;}
              static int build(IPage page){return 1;}
              static int build(List<?> list){return list.size();}
              int safe(){Bean b=new Bean();return convert(b,Bean.class).size();}
              int page(){Page p=null;return build(p);}
            }
            """);
        assertEquals(0,result.findings().size(),result.toString());
    }
    @Test void specializedContainerConversionDoesNotReuseUnknownNullBranch() throws Exception {
        var result=analyze("""
            import java.util.*;import cn.hutool.core.util.ObjectUtil;import cn.hutool.core.collection.CollUtil;import io.github.linpeilie.Converter;
            class Conversion {
              static Converter converter;
              static <T,V> List<V> convert(List<T> list,Class<V> type){if(ObjectUtil.isNull(list))return null;return CollUtil.isEmpty(list)?new ArrayList<>():converter.convert(list,type);}
              static <T,V> V convert(T source,Class<V> type){if(ObjectUtil.isNull(source))return null;return ObjectUtil.isNull(type)?null:converter.convert(source,type);}
              static List<String> guarded(List<String> list){return CollUtil.isEmpty(list)?new ArrayList<>():convert(list,String.class);}
              int safe(List<String> list){return guarded(list).size();}
              int unsafe(List<String> list){return convert(list,String.class).size();}
            }
            """,Map.of("cn.hutool:hutool-core","5.8.27","io.github.linpeilie:mapstruct-plus","1.3.6"));
        assertEquals(Set.of(8),result.findings().stream().map(Models.Finding::line).collect(java.util.stream.Collectors.toSet()),result.toString());
    }
    @Test void arbitraryEqualsNullImplementationsRemainConservative() throws Exception {
        var result=analyze("""
            import cn.hutool.core.util.ObjectUtil;
            final class Unusual {public boolean equals(Object other){return other==null;}}
            class Use {
              static String convert(Unusual source){if(ObjectUtil.isNull(source))return null;return "value";}
              int risk(){return convert(new Unusual()).length();}
            }
            """);
        assertEquals(1,result.findings().size(),result.toString());
    }
    @Test void collectionInterfacesDoNotHideAProjectEqualsNullOverride()throws Exception{
        var result=analyze("""
          import java.util.*;
          import cn.hutool.core.util.ObjectUtil;
          class OddList extends ArrayList<String> {public boolean equals(Object other){return other==null;}}
          class Use {
           static List<String> convert(List<String> source){if(ObjectUtil.isNull(source))return null;return source;}
           int risk(){List<String> source=new OddList();return convert(source).size();}
          }
          """);
        assertEquals(1,result.findings().size(),result.toString());
    }
    @Test void projectShadowJdkTypesDoNotAcquireEqualityContracts() throws Exception {
        var result=analyze("""
            package java.util;
            import cn.hutool.core.util.ObjectUtil;
            class List<T> {public boolean equals(Object other){return true;}int size(){return 0;}}
            class Use {
              static List<String> convert(List<String> source){if(ObjectUtil.isNull(source))return null;return source;}
              int risk(){return convert(new List<String>()).size();}
            }
            """);
        assertEquals(1,result.findings().size(),result.toString());
    }
    @Test void specializesNullArgumentsWithoutPollutingSafeCaller() throws Exception {
        var result=analyze("""
            class Contexts {
              static String convert(String s){if(s==null)return null;return "safe";}
              int unsafe(){return convert(null).length();}
              int safe(){return convert("present").length();}
            }
            """);
        assertEquals(1,result.findings().size(),result.toString()); assertEquals(3,result.findings().getFirst().line());
    }
    @Test void correlatesUnchangedBooleanAndInvalidatesAssignments() throws Exception {
        var result=analyze("""
            class Flags {
              int safe(boolean flag){String s=null;if(flag)s="safe";if(flag)return s.length();return 0;}
              int changedFlag(boolean flag){String s=null;if(flag)s="safe";flag=!flag;if(flag)return s.length();return 0;}
              int changedValue(boolean flag){String s=null;if(flag)s="safe";s=null;if(flag)return s.length();return 0;}
            }
            """);
        assertEquals(Set.of(3,4),result.findings().stream().map(Models.Finding::line).collect(java.util.stream.Collectors.toSet()),result.toString());
        assertFalse(((List<?>)result.modelSummary().get("proofs")).isEmpty());
    }
    @Test void provesOwnedMapWritesButRetainsNullValuesEscapeAndRemoval() throws Exception {
        var result=analyze("""
            import java.util.*;
            class Maps {
              int safe(){Map<String,String> m=new HashMap<>();m.put("k","safe");return m.get("k").length();}
              int nullValue(){Map<String,String> m=new HashMap<>();m.put("k",null);if(m.containsKey("k"))return m.get("k").length();return 0;}
              int escaped(){Map<String,String> m=new HashMap<>();m.put("k","safe");vendor.Library.mutate(m);return m.get("k").length();}
              int removed(){Map<String,String> m=new HashMap<>();m.put("k","safe");m.remove("k");return m.get("k").length();}
              int present(String key){Map<String,String> m=new HashMap<>();m.put(key,"safe");if(m.containsKey(key))return m.get(key).length();return 0;}
            }
            """);
        assertEquals(Set.of(4,5,6),result.findings().stream().map(Models.Finding::line).collect(java.util.stream.Collectors.toSet()),result.toString());
    }
    @Test void usesVersionBoundHutoolEmptyGuardsAndKeepsUnknownVersionsConservative() throws Exception {
        String code="""
            import java.util.*;import cn.hutool.core.collection.CollUtil;
            class Guard {Map<String,List<String>> map;int size(){List<String> values=map.get("k");if(CollUtil.isEmpty(values))values=Collections.singletonList("fallback");return values.size();}}
            """;
        assertEquals(0,analyze(code).findings().size());
        assertEquals(1,analyze(code,Map.of("cn.hutool:hutool-core","unknown-version")).findings().size());
    }
    @Test void retainsNullableUnconstrainedDetailListsAfterCorrectOverloadResolution() throws Exception {
        var result=analyze("""
            import java.util.*;import cn.hutool.core.util.ObjectUtil;
            class Bo {List<String> details;List<String> getDetails(){return details;}}
            class Lists {
              static <T> List<T> convert(List<T> list,Class<T> type){if(ObjectUtil.isNull(list))return null;return list;}
              static <T> T convert(Map<String,Object> map,Class<T> type){return null;}
              int size(Bo bo){List<String> items=convert(bo.getDetails(),String.class);return items.size();}
            }
            """);
        assertEquals(1,result.findings().size(),result.toString());assertEquals(6,result.findings().getFirst().line());
    }
    @Test void retainsRisksAfterHeapArrayConstructorAndLambdaEscapes() throws Exception {
        var result=analyze("""
            import java.util.*;
            class Holder {Holder(Map<String,String> m){} void wipe(){}}
            class Escapes {
              Map<String,String> saved;void wipeSaved(){saved.clear();}
              int field(){Map<String,String> m=new HashMap<>();m.put("k","safe");this.saved=m;wipeSaved();return m.get("k").length();}
              int constructor(){Map<String,String> m=new HashMap<>();m.put("k","safe");new Holder(m).wipe();return m.get("k").length();}
              int array(){Map<String,String> m=new HashMap<>();m.put("k","safe");Map[] box={m};box[0].clear();return m.get("k").length();}
              int closure(){Map<String,String> m=new HashMap<>();m.put("k","safe");vendor.Library.run(()->m.clear());return m.get("k").length();}
              int reference(){Map<String,String> m=new HashMap<>();m.put("k","safe");Runnable clear=m::clear;clear.run();return m.get("k").length();}
              int requiredAlias(){Map<String,String> m=new HashMap<>();m.put("k","safe");Map<String,String> other=Objects.requireNonNull(m);other.clear();return m.get("k").length();}
            }
            """);
        assertEquals(Set.of(5,6,7,8,9,10),result.findings().stream().map(Models.Finding::line).collect(java.util.stream.Collectors.toSet()),result.toString());
    }
    @Test void neverBuildsOwnedFactsForCopiesCustomMapsOrAnonymousOverrides() throws Exception {
        var result=analyze("""
            import java.util.*;
            class Custom extends HashMap<String,String>{@Override public String get(Object key){return null;}}
            class Constructors {
              int copy(String key){Map<String,String> input=new HashMap<>();input.put(key,null);Map<String,String> m=new HashMap<>(input);if(m.containsKey(key))return m.get(key).length();return 0;}
              int custom(){Map<String,String> m=new Custom();m.put("k","safe");return m.get("k").length();}
              int anonymous(){Map<String,String> m=new HashMap<>(){public String get(Object key){return null;}};m.put("k","safe");return m.get("k").length();}
            }
            """);
        assertEquals(Set.of(4,5,6),result.findings().stream().map(Models.Finding::line).collect(java.util.stream.Collectors.toSet()),result.toString());
    }
    @Test void invalidatesAliasingKeysMutableKeysAndIncrementedKeys() throws Exception {
        var result=analyze("""
            import java.util.*;
            class Key {void setId(int id){} }
            class Keys {
              int aliasPut(String key){Map<String,String> m=new HashMap<>();m.put("k","safe");m.put(key,null);return m.get("k").length();}
              int aliasRemove(String key){Map<String,String> m=new HashMap<>();m.put("k","safe");m.remove(key);return m.get("k").length();}
              int mutation(Key key){Map<Key,String> m=new HashMap<>();m.put(key,"safe");key.setId(1);return m.get(key).length();}
              int increment(){int key=0;Map<Integer,String> m=new HashMap<>();m.put(key,"safe");key++;return m.get(key).length();}
            }
            """);
        assertEquals(Set.of(4,5,6,7),result.findings().stream().map(Models.Finding::line).collect(java.util.stream.Collectors.toSet()),result.toString());
    }
    @Test void invalidatesHeapBranchFactsAndIncludesBooleanLoopExitInFixedPoint() throws Exception {
        var result=analyze("""
            class Domain {
              String field;
              void heap(boolean b){if(b)field="a";else field="b";field=null;if(b)field.length();}
              void compound(){boolean b=true;b^=true;String s=null;if(!b)s.length();}
              void loop(){boolean b=true;while(b){b=false;}String s=null;s.length();}
            }
            """);
        assertEquals(Set.of(3,4,5),result.findings().stream().map(Models.Finding::line).collect(java.util.stream.Collectors.toSet()),result.toString());
    }
    @Test void projectShadowClassNeverReceivesExternalNullnessContract() throws Exception {
        var result=analyze("""
            package cn.hutool.core.util;
            class ObjectUtil {static boolean isNotNull(Object value){return true;}}
            class Shadow {int f(){String s=null;if(ObjectUtil.isNotNull(s))return s.length();return 0;}}
            """);
        assertEquals(1,result.findings().size(),result.toString());
    }
    @Test void projectProgressCountsRealPassesAndNeverMovesBackwards() throws Exception {
        Path file=Files.createTempFile(root,"progress-",".java");
        Files.writeString(file,"class Sample {int size(){return 1;}}");
        var snapshots=new ArrayList<ProjectAnalyzer.Progress>();
        ProjectAnalyzer.analyze("progress",List.of(new ProjectAnalyzer.Input("Sample.java",file)),
            List.of("java-null-dereference"),new JavaAnalyzer(),new FrameworkContracts(Map.of()),snapshots::add);
        assertEquals("indexing",snapshots.getFirst().phase());
        assertTrue(snapshots.stream().anyMatch(p->p.phase().equals("analyzing") && p.round()>0));
        for(int i=1;i<snapshots.size();i++) assertTrue(snapshots.get(i).current()>=snapshots.get(i-1).current());
        assertEquals(snapshots.getLast().total(),snapshots.getLast().current());
    }
    @Test void metadataCachesInvalidateForNewAndDuplicateTypesWithoutCachingSummaries() {
        var context=new ProjectContext();
        var unit=SourceParsing.parse("interface Provider {String get();} class Old implements Provider {public String get(){return \"safe\";}} class Use {Provider p;String f(){return p.get();}}");
        context.register("First.java",unit);
        var call=unit.findAll(com.github.javaparser.ast.expr.MethodCallExpr.class).getFirst();
        var owner=context.types.get("Use");
        assertEquals(Set.of("Old"),context.targets(owner,"Provider",call,List.of()).stream().filter(m->m.body).map(m->m.owner.name).collect(java.util.stream.Collectors.toSet()));
        context.register("Second.java",SourceParsing.parse("class New implements Provider {public String get(){return null;}}"));
        assertEquals(Set.of("Old","New"),context.targets(owner,"Provider",call,List.of()).stream().filter(m->m.body).map(m->m.owner.name).collect(java.util.stream.Collectors.toSet()));
        context.register("Duplicate.java",SourceParsing.parse("class Old implements Provider {public String get(){return null;}}"));
        assertEquals(Set.of("New"),context.targets(owner,"Provider",call,List.of()).stream().filter(m->m.body).map(m->m.owner.name).collect(java.util.stream.Collectors.toSet()));
    }
}
