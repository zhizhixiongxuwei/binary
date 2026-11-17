package com.binaryscan.checker.java;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.*;
import static com.binaryscan.checker.java.NullDereferenceAnalyzer.*;

/** Data-only JVMS signatures. No application ClassLoader or reflective loading. */
final class DependencyIndex {
    static final String PATH = ".binaryscan/java-types.json";
    record Member(String name,String descriptor,String signature,int access,List<String> annotations) {}
    record Definition(String name,String parent,List<String> interfaces,List<String> references,String signature,int access,
                      List<Member> fields,List<Member> methods,List<String> annotations,String module,String sourcePrefix,String sha256) {
        boolean matches(String path) { return (sourcePrefix==null||sourcePrefix.isEmpty()) ? !path.startsWith("modules/")&&!path.startsWith("application/") : path.startsWith(sourcePrefix+"/"); }
    }
    record Snapshot(String version,String inputSha256,String classpathOrder,List<Definition> types,List<String> diagnostics,boolean mapperRegistryComplete) {}
    static void load(String text,String inputSha,ProjectContext project) throws IOException {
        Snapshot snapshot=new ObjectMapper().readValue(text,Snapshot.class);
        if(!"java-type-index-v1".equals(snapshot.version)||snapshot.types==null||snapshot.types.size()>6000
            ||inputSha==null||!inputSha.equalsIgnoreCase(snapshot.inputSha256))throw new IOException("type index is not bound to the original input");
        project.mapperRegistryComplete=snapshot.mapperRegistryComplete;
        int members=0;
        for(var d:snapshot.types) {
            if(d.name==null||d.name.length()>1024||!d.name.matches("[\\p{javaJavaIdentifierPart}.$]+")||d.module==null||d.module.length()>1024
                ||d.sha256==null||!d.sha256.matches("[a-f0-9]{64}")||d.sourcePrefix!=null&&!d.sourcePrefix.isEmpty()&&!ProjectCheckController.safePath(d.sourcePrefix)) throw new IOException("invalid type definition identity");
            members+=(d.methods==null?0:d.methods.size())+(d.fields==null?0:d.fields.size());if(members>150000)throw new IOException("dependency member index limit exceeded");
            project.definitions.computeIfAbsent(d.name.replace('$','.'),ignored->new ArrayList<>()).add(d);
        }
        for(var item:project.definitions.entrySet()) {
            if(item.getValue().stream().map(Definition::sha256).distinct().count()!=1) {project.ambiguousTypes.add(item.getKey());continue;}
            Definition d=item.getValue().getFirst();
            var t=new ProjectContext.TypeInfo();t.name=item.getKey();t.path="";t.packageName=t.name.contains(".")?t.name.substring(0,t.name.lastIndexOf('.')):"";
            t.module=d.module;t.classSha256=d.sha256;t.external=true;t.isInterface=(d.access&0x200)!=0;t.isFinal=(d.access&0x10)!=0;t.isEnum=(d.access&0x4000)!=0;t.imports=List.of();t.wildcards=List.of();
            t.parents=new ArrayList<>();
            try {var sig=new Signature(d.signature);t.typeParameters.putAll(sig.formals());while(sig.more())t.parents.add(sig.type());}catch(IllegalArgumentException ignored){t.parents.clear();}
            if(t.parents.isEmpty()){if(d.parent!=null&&!d.parent.isBlank())t.parents.add(d.parent.replace('$','.'));if(d.interfaces!=null)for(var p:d.interfaces)t.parents.add(p.replace('$','.'));}
            for(var f:d.fields==null?List.<Member>of():d.fields){try{t.fields.put(f.name,new ProjectContext.FieldInfo(new Signature(nonempty(f.signature,f.descriptor)).type(),nullable(f.annotations)?Nullness.MAYBE_NULL:Nullness.UNKNOWN,(f.access&8)!=0));}catch(IllegalArgumentException ignored){}}
            for(var m:d.methods==null?List.<Member>of():d.methods){if(m.name.startsWith("<"))continue;try{
                var sig=new Signature(nonempty(m.signature,m.descriptor));var method=new ProjectContext.MethodInfo();method.typeParameters.putAll(sig.formals());sig.expect('(');method.parameters=new ArrayList<>();while(sig.peek()!=')')method.parameters.add(sig.type());sig.expect(')');method.result=sig.type();method.name=m.name;method.owner=t;method.isStatic=(m.access&8)!=0;method.exact=method.isStatic||(m.access&0x12)!=0||t.isFinal;method.varargs=(m.access&0x80)!=0;method.body=false;method.key=t.name+"#"+m.name+"("+String.join(",",method.parameters)+")";if(nullable(m.annotations))method.annotation=Nullness.MAYBE_NULL;t.methods.add(method);
            }catch(IllegalArgumentException ignored){}}
            project.types.put(t.name,t);
        }
        if(snapshot.diagnostics!=null)for(String message:snapshot.diagnostics.stream().limit(100).toList())
            project.diagnostics.put("metadata:"+project.diagnostics.size(),new Models.Diagnostic("JAVA_TYPE_METADATA_LIMIT",PATH,1,1,message));
    }
    private static boolean nullable(List<String> a){return a!=null&&a.stream().anyMatch(x->Set.of("javax.annotation.Nullable","jakarta.annotation.Nullable","javax.annotation.CheckForNull","org.jetbrains.annotations.Nullable","org.springframework.lang.Nullable","org.jspecify.annotations.Nullable").contains(x));}
    private static String nonempty(String a,String b){return a==null||a.isEmpty()?b:a;}
    static final class Signature {
        final String text;int at,depth;
        Signature(String text){this.text=text==null?"":text;if(this.text.length()>16384)throw new IllegalArgumentException("signature limit");}
        boolean more(){return at<text.length();}char peek(){if(!more())throw new IllegalArgumentException("incomplete signature");return text.charAt(at);}
        void expect(char c){if(peek()!=c)throw new IllegalArgumentException("signature token");at++;}
        Map<String,String> formals(){var out=new LinkedHashMap<String,String>();if(!more()||peek()!='<')return out;at++;while(peek()!='>'){int end=text.indexOf(':',at);if(end<at)throw new IllegalArgumentException("formal");String name=text.substring(at,end);at=end+1;String bound=peek()==':'?"java.lang.Object":type();out.put(name,bound);while(peek()==':'){at++;type();}}at++;return out;}
        String type(){if(++depth>32)throw new IllegalArgumentException("signature depth");try{char c=peek();at++;return switch(c){
            case 'B'->"byte";case 'C'->"char";case 'D'->"double";case 'F'->"float";case 'I'->"int";case 'J'->"long";case 'S'->"short";case 'Z'->"boolean";case 'V'->"void";
            case '['->type()+"[]";case '*'->"?";case '+'->"? extends "+type();case '-'->"? super "+type();
            case 'T'->{int end=text.indexOf(';',at);if(end<0)throw new IllegalArgumentException("variable");String n=text.substring(at,end);at=end+1;yield n;}
            case 'L'->{var s=new StringBuilder();while(more()&&peek()!=';'){if(peek()=='<'){at++;var args=new ArrayList<String>();while(peek()!='>')args.add(type());at++;s.append('<').append(String.join(",",args)).append('>');}else{s.append(text.charAt(at++)).append("");}}expect(';');yield s.toString().replace('/','.').replace('$','.');}
            default->throw new IllegalArgumentException("signature type");};}finally{depth--;}}
    }
}
