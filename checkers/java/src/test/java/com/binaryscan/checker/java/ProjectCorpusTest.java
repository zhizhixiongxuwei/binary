package com.binaryscan.checker.java;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.type.TypeReference;
import org.junit.jupiter.api.Test;
import java.nio.file.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.*;

/** Optional regression corpus: reads only a published, immutable source project. */
class ProjectCorpusTest {
 Path corpus(){String value=System.getProperty("binaryscan.corpus.root");assumeTrue(value!=null,"no source corpus supplied");return Path.of(value).toAbsolutePath().normalize();}
 @Test void index()throws Exception{
  var root=corpus();var manifest=new ObjectMapper().readTree(Files.readString(root.resolve("project.json")));var context=new ProjectContext();
  DependencyIndex.load(Files.readString(root.resolve(DependencyIndex.PATH)),manifest.get("inputSha256").asText().toLowerCase(Locale.ROOT),context);
  assertFalse(context.definitions.isEmpty());assertTrue(context.mapperRegistryComplete);
 }
 @Test void protocol()throws Exception{
  var root=corpus();String index=Files.readString(root.resolve(DependencyIndex.PATH));String input=new ObjectMapper().readTree(index).get("inputSha256").asText().toLowerCase(Locale.ROOT);String source="class IndexProbe {}";
  var files=List.of(new Models.ProjectFile(DependencyIndex.PATH,ProjectCheckController.sha256(index.getBytes(java.nio.charset.StandardCharsets.UTF_8)),index.getBytes(java.nio.charset.StandardCharsets.UTF_8).length),new Models.ProjectFile("IndexProbe.java",ProjectCheckController.sha256(source.getBytes()),source.getBytes().length));
  var controller=new ProjectCheckController(new JavaAnalyzer());
  try{
   var request=new Models.ProjectRequest("java-project-v1","index-probe",UUID.randomUUID().toString(),"a".repeat(64),RuleCatalog.VERSION,List.of("java-null-dereference"),files,Map.of(),FrameworkContracts.digestJson(Map.of()),input);
   var decoded=new ObjectMapper().readValue(new ObjectMapper().writeValueAsString(request),Models.ProjectRequest.class);
   var session=controller.create(decoded);controller.upload(session.sessionId(),new Models.ProjectUpload(List.of(new Models.SourceFile(DependencyIndex.PATH,index),new Models.SourceFile("IndexProbe.java",source))));
   var result=controller.analyze(session.sessionId());assertTrue(((Number)result.modelSummary().get("dependencyTypeDefinitions")).intValue()>0,result.diagnosticDetails().toString());
  }finally{controller.close();}
 }
 @Test void allRules()throws Exception{
  var root=corpus();var mapper=new ObjectMapper();var manifest=mapper.readTree(Files.readString(root.resolve("project.json")));var inputs=new ArrayList<ProjectAnalyzer.Input>();
  for(var file:manifest.get("files")){String path=file.get("path").asText();var source=root.resolve(path).normalize();assertTrue(source.startsWith(root));inputs.add(new ProjectAnalyzer.Input(path,source));}
  inputs.add(new ProjectAnalyzer.Input(DependencyIndex.PATH,root.resolve(DependencyIndex.PATH)));
  var frameworks=mapper.readValue(Files.readString(Path.of(System.getProperty("binaryscan.corpus.frameworks"))),new TypeReference<Map<String,String>>(){});
  var result=ProjectAnalyzer.analyze("corpus",inputs,RuleCatalog.IDS.stream().sorted().toList(),new JavaAnalyzer(),new FrameworkContracts(frameworks),p->{},manifest.get("inputSha256").asText());
  String output=System.getProperty("binaryscan.corpus.output");if(output!=null)Files.writeString(Path.of(output),mapper.writeValueAsString(result));
  assertEquals(result.coverage().totalFiles(),result.coverage().analyzedFiles());
  assertTrue(result.diagnosticDetails().stream().noneMatch(d->Set.of("JAVA_TIME_LIMIT","JAVA_ANALYZER_INTERNAL_ERROR","JAVA_TYPE_INDEX_INVALID").contains(d.code())),result.diagnosticDetails().toString());
 }
}
