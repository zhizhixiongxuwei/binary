package com.binaryscan.checker.java;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PreDestroy;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import java.io.*;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.zip.ZipFile;

@RestController
final class ImpactSessionController {
    static final long INPUT_LIMIT=256L<<20;
    static final class Session {Path directory;ImpactGraph.Request request;Instant expires;boolean running;Process process;}
    private final Map<String,Session> sessions=new ConcurrentHashMap<>();
    private final ScheduledExecutorService cleaner=Executors.newSingleThreadScheduledExecutor(r->{Thread t=new Thread(r,"impact-session-cleanup");t.setDaemon(true);return t;});
    private final ObjectMapper mapper=new ObjectMapper();
    ImpactSessionController(){cleaner.scheduleWithFixedDelay(()->{for(var e:sessions.entrySet())if(e.getValue().expires.isBefore(Instant.now()))release(e.getKey());},60,60,TimeUnit.SECONDS);}
    @GetMapping("/v1/java-impact/capabilities")
    Map<String,Object> capabilities(){return Map.of("schemaVersion","java-impact-v1","engineVersion",ImpactGraph.VERSION,"javaReleases",List.of(8,11,17,21),"jdkModel","reviewed-no-callback-primitives; other unresolved runtime behavior blocks negative proofs","maxInputBytes",INPUT_LIMIT);}
    @PostMapping("/v1/java-impact/sessions")
    synchronized Map<String,String> create(HttpServletRequest http)throws Exception{
        byte[] json=http.getInputStream().readNBytes((1<<20)+1);if(json.length>1<<20)throw new ResponseStatusException(HttpStatus.PAYLOAD_TOO_LARGE,"impact request limit");
        ImpactGraph.Request request=mapper.readValue(json,ImpactGraph.Request.class);
        if(sessions.size()>=4)throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS,"impact capacity exhausted");
        if(!"java-impact-v1".equals(request.schemaVersion())||request.inputSha256()==null||!request.inputSha256().matches("[a-f0-9]{64}")
            ||!Set.of(8,11,17,21).contains(request.javaRelease())||request.applicationType()==null||!Set.of("java","spring","war").contains(request.applicationType())
            ||request.inputs()==null||request.inputs().isEmpty()||request.inputs().size()>100||request.targets()==null||request.targets().size()>10000
            ||request.entryPoints()!=null&&request.entryPoints().size()>1000)throw bad("invalid impact request");
        long bytes=0;for(var i:request.inputs()){if(i.sha256()==null||!i.sha256().matches("[a-f0-9]{64}")||i.size()<1||i.size()>INPUT_LIMIT||i.logicalPath()==null||i.logicalPath().length()>2048)throw bad("invalid input identity");bytes+=i.size();}
        if(bytes>INPUT_LIMIT||!request.inputs().getFirst().sha256().equals(request.inputSha256()))throw bad("invalid input budget");
        for(var t:request.targets())if(t.occurrenceId()==null||!t.occurrenceId().matches("[a-f0-9]{64}")||t.componentPath()==null||t.ruleId()==null||t.prefixes()==null||t.prefixes().size()>100||t.prefixes().stream().anyMatch(p->p.isEmpty()||p.length()>512))throw bad("invalid target");
        Session s=new Session();s.request=request;s.directory=Files.createTempDirectory("java-impact-");s.expires=Instant.now().plusSeconds(600);String id=UUID.randomUUID().toString();
        mapper.writeValue(s.directory.resolve("request.json").toFile(),request);sessions.put(id,s);return Map.of("sessionId",id);
    }
    @PutMapping(path="/v1/java-impact/sessions/{id}/inputs/{index}",consumes=MediaType.APPLICATION_OCTET_STREAM_VALUE)
    Map<String,String> upload(@PathVariable String id,@PathVariable int index,HttpServletRequest request)throws Exception{
        Session s=session(id);synchronized(s){if(s.running)throw new ResponseStatusException(HttpStatus.CONFLICT,"analysis sealed");if(index<0||index>=s.request.inputs().size())throw bad("invalid input index");
            var expected=s.request.inputs().get(index);if(request.getContentLengthLong()>expected.size())throw bad("input size mismatch");Path file=s.directory.resolve("input-"+index+".jar");Path temp=s.directory.resolve("upload-"+index+".tmp");
            try(var in=request.getInputStream();var out=Files.newOutputStream(temp)){long n=in.transferTo(new OutputStream(){long count;public void write(int v)throws IOException{write(new byte[]{(byte)v});}public void write(byte[] b,int off,int len)throws IOException{count+=len;if(count>expected.size())throw new IOException("input limit");out.write(b,off,len);}});if(n!=expected.size())throw bad("input size mismatch");}
            if(!ImpactGraph.sha(Files.readAllBytes(temp)).equals(expected.sha256())){Files.deleteIfExists(temp);throw bad("input digest mismatch");}Files.move(temp,file,StandardCopyOption.REPLACE_EXISTING);return Map.of("status","verified");}
    }
    @PostMapping("/v1/java-impact/sessions/{id}/analyze")
    ImpactGraph.Response analyze(@PathVariable String id)throws Exception{
        Session s=session(id);synchronized(s){if(s.running)throw new ResponseStatusException(HttpStatus.CONFLICT,"already running");for(int i=0;i<s.request.inputs().size();i++)if(!Files.isRegularFile(s.directory.resolve("input-"+i+".jar")))throw new ResponseStatusException(HttpStatus.CONFLICT,"incomplete upload");if(!AnalysisSlot.HEAVY.tryAcquire())throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS,"heavy analyzer busy");s.running=true;}
        try{
            var command=childCommand(s.directory);Process child=new ProcessBuilder(command).redirectError(ProcessBuilder.Redirect.DISCARD).redirectOutput(ProcessBuilder.Redirect.DISCARD).start();s.process=child;
            try{if(!child.waitFor(180,TimeUnit.SECONDS)||child.exitValue()!=0)return unknown(s,"CHILD_ANALYSIS_FAILED_OR_LIMITED");Path result=s.directory.resolve("result.json");if(!Files.isRegularFile(result)||Files.size(result)>16L<<20)return unknown(s,"RESULT_LIMIT");return mapper.readValue(result.toFile(),ImpactGraph.Response.class);}
            finally{if(child.isAlive()){child.destroyForcibly();child.waitFor(5,TimeUnit.SECONDS);}s.process=null;}
        }finally{AnalysisSlot.HEAVY.release();}
    }
    static List<String> childCommand(Path directory)throws IOException{
        String cp=System.getProperty("java.class.path");var cmd=new ArrayList<String>();cmd.add(Path.of(System.getProperty("java.home"),"bin","java").toString());cmd.add("-Xmx512m");
        boolean boot=false;if(!cp.contains(File.pathSeparator)&&cp.endsWith(".jar")){try(var zip=new ZipFile(cp)){boot=zip.getEntry("org/springframework/boot/loader/launch/PropertiesLauncher.class")!=null;}}
        if(boot)cmd.add("-Dloader.main="+ImpactMain.class.getName());cmd.add("-cp");cmd.add(cp);cmd.add(boot?"org.springframework.boot.loader.launch.PropertiesLauncher":ImpactMain.class.getName());cmd.add(directory.toString());return cmd;
    }
    private ImpactGraph.Response unknown(Session s,String reason){var results=new TreeMap<String,ImpactGraph.Result>();for(var t:s.request.targets())results.put(t.occurrenceId(),new ImpactGraph.Result("unknown",List.of(),List.of(reason),false,ImpactGraph.VERSION,s.request.inputSha256(),"",t.ruleId()));return new ImpactGraph.Response("java-impact-v1",s.request.inputSha256(),s.request.javaRelease(),"",results,0,0,0,List.of(reason));}
    @DeleteMapping("/v1/java-impact/sessions/{id}")
    Map<String,String> release(@PathVariable String id){Session s=sessions.remove(id);if(s!=null){if(s.process!=null)s.process.destroyForcibly();try(var files=Files.walk(s.directory)){for(Path p:files.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(p);}catch(IOException ignored){}}return Map.of("status","released");}
    private Session session(String id){Session s=sessions.get(id);if(s==null||s.expires.isBefore(Instant.now())){release(id);throw new ResponseStatusException(HttpStatus.NOT_FOUND,"session expired");}return s;}
    private static ResponseStatusException bad(String message){return new ResponseStatusException(HttpStatus.BAD_REQUEST,message);}
    @PreDestroy void stop(){cleaner.shutdownNow();for(String id:List.copyOf(sessions.keySet()))release(id);}
}
