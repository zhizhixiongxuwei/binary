package com.binaryscan.checker.java;

import java.io.IOException;
import java.util.*;

/** Project security results are computed once, separate from the nullness lattice. */
final class SecurityAnalysis {
    static final String VERSION="java-security-flow-v1";
    static final String WEB_EXEC="java-web-input-execution", CLASS_LOAD="java-untrusted-class-definition",
        WEB_IMPLANT="java-suspicious-web-component", AUTH_BYPASS="java-hidden-authentication-path",
        JACKSON="java-jackson-polymorphic-deserialization", JWT="java-jwt-hardcoded-signing-key";
    static final Set<String> FLOW_RULES=Set.of("java-sql-injection","java-command-injection","java-dynamic-code-execution",WEB_EXEC,CLASS_LOAD,WEB_IMPLANT,AUTH_BYPASS,JACKSON,JWT);
    final List<Models.Finding> findings;
    final Map<String,Object> summary;
    SecurityAnalysis(List<Models.Finding> findings,Map<String,Object> summary){this.findings=findings;this.summary=summary;}
    static SecurityAnalysis analyze(List<ProjectAnalyzer.Input> sources,List<ProjectAnalyzer.Input> resources,ProjectContext context,Set<String> rules)throws IOException{
        var parsed=SecurityResources.read(resources);context.diagnostics.putAll(diagnostics(parsed.diagnostics));
        return new SecurityFlow(context,rules,parsed).analyze(sources);
    }
    private static Map<String,Models.Diagnostic> diagnostics(List<Models.Diagnostic> list){var result=new LinkedHashMap<String,Models.Diagnostic>();for(var d:list)result.put(d.code()+":"+d.path(),d);return result;}
    static boolean enabled(Set<String> rules){return rules.stream().anyMatch(FLOW_RULES::contains);}
}
