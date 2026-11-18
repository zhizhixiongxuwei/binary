package com.binaryscan.checker.java;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class ImpactGraphTest {
    @TempDir Path temp;
    @Test void actualJavaArchivesDistinguishReachabilityAndReflection()throws Exception{
        Path root=Path.of("../../test-fixtures/sca");Assumptions.assumeTrue(Files.isDirectory(root),"generate script/fixtures/sca_samples.py");
        for(String variant:List.of("reachable","unreachable","reflective"))for(String layout:List.of("plain","boot","war")){
            String name=variant+"-"+layout+(layout.equals("war")?".war":".jar");byte[] bytes=Files.readAllBytes(root.resolve(name));String sha=ImpactGraph.sha(bytes);
            Files.write(temp.resolve("input-0.jar"),bytes);String dependency=layout.equals("boot")?"BOOT-INF/lib/":layout.equals("war")?"WEB-INF/lib/":"lib/";
            var target=new ImpactGraph.Target("a".repeat(64),name+"!/"+dependency+"commons-text-1.9.jar","text-rule",List.of("org/apache/commons/text/StringSubstitutor","org/apache/commons/text/lookup/"));
            var request=new ImpactGraph.Request("java-impact-v1",sha,8,"java",List.of(),List.of(new ImpactGraph.Input(sha,name,bytes.length)),List.of(target));
            var result=new ImpactGraph(request).analyze(temp).results().get(target.occurrenceId());
            String expected=variant.equals("reachable")?"reachable":variant.equals("unreachable")?"not_reachable":"unknown";
            assertEquals(expected,result.state(),name+": "+result.diagnostics());
            if(expected.equals("reachable"))assertFalse(result.path().isEmpty());
            if(expected.equals("not_reachable"))assertTrue(result.complete());
        }
    }
    @Test void mismatchedInputNeverProducesVerdict()throws Exception{
        Files.write(temp.resolve("input-0.jar"),new byte[]{1,2});
        var request=new ImpactGraph.Request("java-impact-v1","a".repeat(64),21,"java",List.of(),List.of(new ImpactGraph.Input("a".repeat(64),"x.jar",2)),List.of());
        assertThrows(Exception.class,()->new ImpactGraph(request).analyze(temp));
    }
}
