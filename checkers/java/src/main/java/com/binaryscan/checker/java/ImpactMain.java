package com.binaryscan.checker.java;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.*;
/** Child JVM entry point; application bytecode is never added to its classpath. */
public final class ImpactMain {
    public static void main(String[] args)throws Exception{
        var mapper=new ObjectMapper();Path directory=Path.of(args[0]);
        var request=mapper.readValue(directory.resolve("request.json").toFile(),ImpactGraph.Request.class);
        var result=new ImpactGraph(request).analyze(directory);
        mapper.writeValue(directory.resolve("result.json").toFile(),result);
    }
}
