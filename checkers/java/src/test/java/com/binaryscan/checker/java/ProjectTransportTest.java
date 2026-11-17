package com.binaryscan.checker.java;

import org.junit.jupiter.api.Test;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.web.server.ResponseStatusException;
import java.nio.charset.StandardCharsets;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class ProjectTransportTest {
 @Test void jsonTransportSupportsTypeSidecarsAboveFourMiBButOrdinarySourcesRemainBounded()throws Exception{
  var builder=new Jackson2ObjectMapperBuilder();new JavaCheckerApplication().projectJsonLimits().customize(builder);
  com.fasterxml.jackson.databind.ObjectMapper mapper=builder.build();String content="x".repeat(21<<20);
  byte[] body=mapper.writeValueAsBytes(Map.of("files",List.of(Map.of("path",DependencyIndex.PATH,"content",content))));
  var factory=com.fasterxml.jackson.core.JsonFactory.builder().streamReadConstraints(ProjectRequestLimitFilter.constraints()).build();
  try(var parser=factory.createParser(body)){while(parser.nextToken()!=null)if(parser.currentToken().isScalarValue())parser.getTextLength();}
  assertEquals(content.length(),mapper.readTree(body).get("files").get(0).get("content").asText().length());
  var controller=new ProjectCheckController(new JavaAnalyzer());try{
   var invalid=new Models.ProjectRequest("java-project-v1","project","run","a".repeat(64),RuleCatalog.VERSION,List.of("java-null-dereference"),List.of(new Models.ProjectFile("large.java","b".repeat(64),5<<20)));
   assertEquals(400,assertThrows(ResponseStatusException.class,()->controller.create(invalid)).getStatusCode().value());
  }finally{controller.close();}
 }
}
