package com.binaryscan.checker.java;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class WrapperCryptoTest {
 @TempDir Path root;
 @Test void recognizesVersionBoundWrappersAndFinalAlgorithmsWithoutCallingChecksumsExploits()throws Exception{
  var file=root.resolve("Crypto.java");Files.writeString(file,"""
   import cn.hutool.crypto.SecureUtil;
   import cn.hutool.crypto.digest.DigestUtil;
   import cn.hutool.crypto.symmetric.AES;
   import java.security.MessageDigest;
   class Crypto {
    static final String ALGORITHM="M"+"D5";
    static String mutable="MD5";
    Object fixed()throws Exception{return MessageDigest.getInstance(ALGORITHM);}
    Object unknown()throws Exception{return MessageDigest.getInstance(mutable);}
    String checksum(String value){return DigestUtil.md5Hex(value);}
    Object aes(byte[] key){return new AES(key);}
    Object explicitSafe(byte[] key){return new AES("GCM","NoPadding",key);}
   }
   """);
  var inputs=List.of(new ProjectAnalyzer.Input("Crypto.java",file));var rules=List.of("java-weak-message-digest","java-weak-cipher");
  var r=ProjectAnalyzer.analyze("crypto",inputs,rules,new JavaAnalyzer(),new FrameworkContracts(Map.of("cn.hutool:hutool-crypto","5.8.27")));
  assertEquals(Set.of(8,10,11),r.findings().stream().map(Models.Finding::line).collect(java.util.stream.Collectors.toSet()),r.toString());
  assertTrue(r.findings().stream().anyMatch(f->f.message().contains("deduplication")));
  var unknown=ProjectAnalyzer.analyze("crypto",inputs,rules,new JavaAnalyzer());assertEquals(1,unknown.findings().size(),unknown.toString());
 }
}
