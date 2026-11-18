package com.binaryscan.checker.java;

import org.springframework.asm.*;
import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.jar.Manifest;
import java.util.zip.*;
import static org.springframework.asm.Opcodes.*;

/** Bounded conservative CHA. Never loads or executes a submitted class. */
final class ImpactGraph {
    static final String VERSION = "asm-cha-v1";
    record Input(String sha256, String logicalPath, long size) {}
    record Target(String occurrenceId, String componentPath, String ruleId, List<String> prefixes) {}
    record Request(String schemaVersion, String inputSha256, int javaRelease, String applicationType,
                   List<String> entryPoints, List<Input> inputs, List<Target> targets) {}
    record Result(String state, List<String> path, List<String> diagnostics, boolean complete,
                  String engineVersion, String inputSha256, String viewDigest, String ruleId) {}
    record Response(String schemaVersion, String inputSha256, int javaRelease, String viewDigest,
                    Map<String,Result> results, int classes, int methods, int edges, List<String> diagnostics) {}
    record Call(int opcode,String owner,String name,String descriptor) {}
    static final class Method {
        String key,owner,name,descriptor; int access; boolean application; boolean dynamic;
        List<Call> calls = new ArrayList<>(); Set<String> initialize = new TreeSet<>();
    }
    static final class Klass {
        String name,parent,origin,digest; boolean application; List<String> interfaces;
        Map<String,Method> methods = new TreeMap<>();
    }
    private final Request request;
    private final Map<String,Klass> classes = new TreeMap<>();
    private final Map<String,Method> methods = new TreeMap<>();
    private final Set<String> diagnostics = new TreeSet<>();
    private long expanded; private int entries,modules,edges,methodCount;
    private boolean complete=true;
    ImpactGraph(Request request) { this.request=request; }

    Response analyze(Path directory) throws Exception {
        for(int i=0;i<request.inputs().size();i++) {
            var input=request.inputs().get(i); byte[] body=Files.readAllBytes(directory.resolve("input-"+i+".jar"));
            if(body.length!=input.size() || !sha(body).equals(input.sha256())) throw new IOException("input digest mismatch");
            readArchive(body,input.logicalPath(),i==0,0);
        }
        for(Klass k:classes.values()) for(Method m:k.methods.values()) methods.put(m.key,m);
        var roots=new TreeSet<String>(); boolean hasEntry=false;
        for(Method m:methods.values()) {
            if(!m.application)continue;
            boolean explicit=request.entryPoints()!=null && request.entryPoints().contains(m.key);
            boolean main=m.name.equals("main")&&m.descriptor.equals("([Ljava/lang/String;)V")&&(m.access&ACC_STATIC)!=0;
            // Root every application public method for framework lifecycles;
            // this overapproximation includes Web, scheduled and callback entry.
            boolean framework=!request.applicationType().equals("java") && ((m.access&ACC_PUBLIC)!=0||m.name.equals("<init>"));
            if(explicit||main||framework){roots.add(m.key);hasEntry=true;}
            if(m.name.equals("<clinit>"))roots.add(m.key);
        }
        if(request.entryPoints()!=null)for(String root:request.entryPoints())if(!methods.containsKey(root))gap("ENTRY_NOT_RESOLVED:"+root);
        if(!hasEntry)gap("NO_SUPPORTED_APPLICATION_ENTRY");
        var parent=new LinkedHashMap<String,String>(); var queue=new ArrayDeque<String>();
        for(String r:roots){parent.put(r,"");queue.add(r);}
        for(String r:roots)initialize(methods.get(r).owner,r,parent,queue,new HashSet<>());
        while(!queue.isEmpty()) {
            check();String key=queue.remove();Method m=methods.get(key);if(m==null){gap("MISSING_METHOD:"+key);continue;}
            if((m.access&ACC_NATIVE)!=0)gap("NATIVE_METHOD:"+key);
            if(m.dynamic)gap("UNMODELED_DYNAMIC_CALL:"+key);
            for(String owner:m.initialize)initialize(owner,key,parent,queue,new HashSet<>());
            for(Call call:m.calls){
                Set<String> targets=resolve(call);
                if(targets.isEmpty()&&!safeRuntime(call))gap("UNRESOLVED_CALL:"+call.owner+"#"+call.name+call.descriptor);
                for(String target:targets){if(++edges>300000)throw new IOException("CALL_EDGE_LIMIT");enqueue(target,key,parent,queue);}
                if(call.opcode==INVOKESTATIC||call.name.equals("<init>"))initialize(call.owner,key,parent,queue,new HashSet<>());
            }
            if(parent.size()>100000)throw new IOException("REACHABLE_METHOD_LIMIT");
        }
        var digest=MessageDigest.getInstance("SHA-256");digest.update(Integer.toString(request.javaRelease()).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        for(Klass k:classes.values())digest.update(("\n"+k.name+":"+k.origin+":"+k.digest).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String view=HexFormat.of().formatHex(digest.digest());
        var results=new TreeMap<String,Result>();
        for(Target t:request.targets()) {
            String hit=null;boolean present=false;
            for(Klass k:classes.values())if(k.origin.equals(t.componentPath())&&t.prefixes().stream().anyMatch(k.name::startsWith)){
                present=true;for(Method m:k.methods.values())if(parent.containsKey(m.key)){hit=m.key;break;}if(hit!=null)break;
            }
            var reasons=new ArrayList<>(diagnostics);if(!present)reasons.add("VULNERABLE_TARGET_NOT_IDENTIFIED");
            String state=hit!=null?"reachable":complete&&present&&hasEntry?"not_reachable":"unknown";
            var path=new ArrayList<String>();if(hit!=null){String cursor=hit;while(cursor!=null&&!cursor.isEmpty()&&path.size()<256){path.add(cursor);cursor=parent.get(cursor);}Collections.reverse(path);}
            results.put(t.occurrenceId(),new Result(state,path,reasons,complete&&present&&hasEntry,VERSION,request.inputSha256(),view,t.ruleId()));
        }
        return new Response("java-impact-v1",request.inputSha256(),request.javaRelease(),view,results,classes.size(),methods.size(),edges,new ArrayList<>(diagnostics));
    }
    private void enqueue(String target,String from,Map<String,String>parent,Deque<String>queue){if(!parent.containsKey(target)){parent.put(target,from);queue.add(target);}}
    private void initialize(String owner,String from,Map<String,String>parent,Deque<String>queue,Set<String>seen){
        if(!seen.add(owner))return;Klass k=classes.get(owner);if(k==null){if(!owner.equals("java/lang/Object"))gap("UNRESOLVED_INITIALIZER:"+owner);return;}
        Method cl=k.methods.get("<clinit>()V");if(cl!=null)enqueue(cl.key,from,parent,queue);
        if(k.parent!=null)initialize(k.parent,from,parent,queue,seen);
        for(String itf:k.interfaces)initialize(itf,from,parent,queue,seen);
    }
    private Set<String> resolve(Call call){
        var out=new TreeSet<String>();
        if(call.opcode==INVOKESTATIC||call.opcode==INVOKESPECIAL){Method m=find(call.owner,call.name+call.descriptor,new HashSet<>());if(m!=null)out.add(m.key);return out;}
        for(Klass k:classes.values())if(assignable(k.name,call.owner,new HashSet<>())){Method m=find(k.name,call.name+call.descriptor,new HashSet<>());if(m!=null&&(m.access&ACC_ABSTRACT)==0)out.add(m.key);}
        return out;
    }
    private Method find(String owner,String signature,Set<String>seen){if(!seen.add(owner))return null;Klass k=classes.get(owner);if(k==null)return null;Method m=k.methods.get(signature);if(m!=null)return m;if(k.parent!=null){m=find(k.parent,signature,seen);if(m!=null)return m;}for(String itf:k.interfaces){m=find(itf,signature,seen);if(m!=null)return m;}return null;}
    private boolean assignable(String type,String owner,Set<String>seen){if(type.equals(owner))return true;if(!seen.add(type))return false;Klass k=classes.get(type);if(k==null)return false;if(k.parent!=null&&assignable(k.parent,owner,seen))return true;return k.interfaces.stream().anyMatch(i->assignable(i,owner,seen));}
    // Only reviewed no-callback runtime operations are modeled. Other JDK
    // calls keep negative conclusions unknown instead of assuming a closed JDK.
    private boolean safeRuntime(Call c){
        return c.owner.equals("java/lang/Object")&&c.name.equals("<init>")&&c.descriptor.equals("()V")
            ||c.owner.equals("java/lang/String")&&Set.of("length()I","isEmpty()Z","charAt(I)C","equals(Ljava/lang/Object;)Z").contains(c.name+c.descriptor);
    }
    private void readArchive(byte[] body,String origin,boolean primary,int depth)throws Exception{
        check();if(depth>4||++modules>512)throw new IOException("ARCHIVE_MODULE_LIMIT");
        var all=new LinkedHashMap<String,byte[]>();
        try(var zip=new ZipInputStream(new ByteArrayInputStream(body))){ZipEntry e;while((e=zip.getNextEntry())!=null){
            if(++entries>120000)throw new IOException("ARCHIVE_ENTRY_LIMIT");String name=e.getName();
            if(name.startsWith("/")||name.contains("\\")||Arrays.asList(name.split("/")).contains("..")||all.containsKey(name))throw new IOException("UNSAFE_OR_DUPLICATE_ENTRY");
            if(e.isDirectory())continue;byte[] value=zip.readNBytes((256<<20)+1);expanded+=value.length;
            if(value.length>256<<20||expanded>768L<<20)throw new IOException("ARCHIVE_EXPANSION_LIMIT");all.put(name,value);
        }}
        boolean multi=false;byte[] mf=all.get("META-INF/MANIFEST.MF");if(mf!=null){var m=new Manifest(new ByteArrayInputStream(mf));multi="true".equalsIgnoreCase(m.getMainAttributes().getValue("Multi-Release"));if(m.getMainAttributes().getValue("Class-Path")!=null)gap("MANIFEST_CLASSPATH_UNVERIFIED");}
        record Candidate(int release,String name,byte[] value){}
        var selected=new TreeMap<String,Candidate>();
        for(var entry:all.entrySet()){
            String name=entry.getKey();if(name.endsWith(".jar")){readArchive(entry.getValue(),origin+"!/"+name,false,depth+1);continue;}if(!name.endsWith(".class"))continue;
            int release=0;String effective=name;
            if(name.startsWith("META-INF/versions/")) {if(!multi)continue;String[] parts=name.split("/",4);if(parts.length!=4)throw new IOException("INVALID_MULTI_RELEASE_ENTRY");release=Integer.parseInt(parts[2]);if(release>request.javaRelease())continue;effective=parts[3];}
            if(effective.equals("module-info.class"))continue;
            Candidate prior=selected.get(effective);if(prior==null||release>prior.release())selected.put(effective,new Candidate(release,name,entry.getValue()));
        }
        for(Candidate c:selected.values())readClass(c.value(),origin,primary&&!c.name().startsWith("org/springframework/boot/loader/"));
    }
    private void readClass(byte[] data,String origin,boolean application)throws Exception{
        if(data.length<8||data.length>4<<20)throw new IOException("CLASS_LIMIT");int major=((data[6]&255)<<8)|(data[7]&255);if(major>request.javaRelease()+44){gap("BYTECODE_NEWER_THAN_TARGET:"+origin);return;}
        if(classes.size()>=50000)throw new IOException("CLASS_COUNT_LIMIT");
        Klass k=new Klass();k.origin=origin;k.application=application;k.digest=sha(data);
        new ClassReader(data).accept(new ClassVisitor(ASM9){
            public void visit(int version,int access,String name,String signature,String parent,String[] interfaces){k.name=name;k.parent=parent;k.interfaces=List.of(interfaces);}
            public MethodVisitor visitMethod(int access,String name,String descriptor,String signature,String[] exceptions){
                Method m=new Method();m.owner=k.name;m.name=name;m.descriptor=descriptor;m.access=access;m.application=application;m.key=k.name+"#"+name+descriptor;k.methods.put(name+descriptor,m);
                if(++methodCount>100000)throw new IllegalArgumentException("METHOD_LIMIT");
                return new MethodVisitor(ASM9){
                    public void visitMethodInsn(int opcode,String owner,String method,String desc,boolean itf){m.calls.add(new Call(opcode,owner,method,desc));if(m.calls.size()>10000)throw new IllegalArgumentException("METHOD_CALL_LIMIT");}
                    public void visitFieldInsn(int opcode,String owner,String name,String desc){if(opcode==GETSTATIC||opcode==PUTSTATIC)m.initialize.add(owner);}
                    public void visitTypeInsn(int opcode,String type){if(opcode==NEW)m.initialize.add(type);}
                    public void visitLdcInsn(Object value){if(value instanceof ConstantDynamic)m.dynamic=true;}
                    public void visitInvokeDynamicInsn(String name,String descriptor,Handle bootstrap,Object...arguments){
                        if(bootstrap.getOwner().equals("java/lang/invoke/LambdaMetafactory")){boolean found=false;for(Object a:arguments)if(a instanceof Handle h){found=true;int op=h.getTag()==H_INVOKESTATIC?INVOKESTATIC:h.getTag()==H_INVOKESPECIAL||h.getTag()==H_NEWINVOKESPECIAL?INVOKESPECIAL:INVOKEVIRTUAL;m.calls.add(new Call(op,h.getOwner(),h.getName(),h.getDesc()));}if(!found)m.dynamic=true;}
                        else m.dynamic=true;
                    }
                };
            }
        },ClassReader.SKIP_FRAMES|ClassReader.SKIP_DEBUG);
        Klass prior=classes.putIfAbsent(k.name,k);if(prior!=null)gap("DUPLICATE_CLASS:"+k.name);
    }
    private void gap(String diagnostic){complete=false;if(diagnostics.size()<100)diagnostics.add(diagnostic);}
    private void check()throws IOException{if(Thread.currentThread().isInterrupted())throw new IOException("ANALYSIS_CANCELLED");}
    static String sha(byte[] value)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));}
}
