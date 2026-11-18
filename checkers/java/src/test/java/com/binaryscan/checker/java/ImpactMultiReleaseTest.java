package com.binaryscan.checker.java;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.asm.ClassWriter;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;
import static org.springframework.asm.Opcodes.*;
import static org.junit.jupiter.api.Assertions.*;

class ImpactMultiReleaseTest {
 @TempDir Path temp;
 byte[] main(int release,boolean invokes) {
  var c=new ClassWriter(0);c.visit(release+44,ACC_PUBLIC,"Application",null,"java/lang/Object",null);
  var m=c.visitMethod(ACC_PUBLIC|ACC_STATIC,"main","([Ljava/lang/String;)V",null,null);m.visitCode();if(invokes)m.visitMethodInsn(INVOKESTATIC,"Vulnerable","trigger","()V",false);m.visitInsn(RETURN);m.visitMaxs(0,1);m.visitEnd();c.visitEnd();return c.toByteArray();
 }
 @Test void selectsEffectiveBytecodeForEachTargetJavaWithoutReusingViews() throws Exception {
  var vulnerable=new ClassWriter(0);vulnerable.visit(V1_8,ACC_PUBLIC,"Vulnerable",null,"java/lang/Object",null);var method=vulnerable.visitMethod(ACC_PUBLIC|ACC_STATIC,"trigger","()V",null,null);method.visitCode();method.visitInsn(RETURN);method.visitMaxs(0,0);method.visitEnd();vulnerable.visitEnd();
  Path archive=temp.resolve("input-0.jar");try(var z=new ZipOutputStream(Files.newOutputStream(archive))) {
   for(var e:Map.of("META-INF/MANIFEST.MF","Manifest-Version: 1.0\nMulti-Release: true\n\n".getBytes(),"Application.class",main(8,false),"META-INF/versions/11/Application.class",main(11,true),"Vulnerable.class",vulnerable.toByteArray()).entrySet()){z.putNextEntry(new ZipEntry(e.getKey()));z.write(e.getValue());z.closeEntry();}
  }
  byte[] bytes=Files.readAllBytes(archive);String sha=ImpactGraph.sha(bytes);String view8=null;
  for(int release:List.of(8,11,17,21)) {
   var target=new ImpactGraph.Target("a".repeat(64),"sample.jar","test",List.of("Vulnerable"));
   var result=new ImpactGraph(new ImpactGraph.Request("java-impact-v1",sha,release,"java",List.of(),List.of(new ImpactGraph.Input(sha,"sample.jar",bytes.length)),List.of(target))).analyze(temp).results().get(target.occurrenceId());
   assertEquals(release==8?"not_reachable":"reachable",result.state());
   if(release==8)view8=result.viewDigest();else assertNotEquals(view8,result.viewDigest());
  }
 }
}
