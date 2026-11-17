package com.binaryscan.checker.java;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.expr.*;
import java.util.*;

/** Version-matched wrappers report algorithm/configuration risk, not exploitation. */
final class WrapperCrypto {
 record Hit(String rule,String message) {}
 static Hit call(MethodCallExpr call,ProjectContext context,CompilationUnit unit){
  if(context==null||!context.contracts.exact("cn.hutool:hutool-crypto","5.8.27"))return null;
  String raw=call.getScope().map(Object::toString).orElse("");var owner=context.owner(call,unit);String type=context.qualify(raw,owner);
  if(!context.externalContractsAllowed(type))return null;
  if(Set.of("cn.hutool.crypto.SecureUtil","cn.hutool.crypto.digest.DigestUtil").contains(type)){
   if(Set.of("md5","md5Hex","md5Hex16","sha1","sha1Hex").contains(call.getNameAsString()))return new Hit("java-weak-message-digest","Hutool 5.8.27 wrapper selects MD5/SHA-1; security purpose is unproven and ordinary deduplication/checksums require separate review");
   if(Set.of("des","desede","rc4").contains(call.getNameAsString()))return new Hit("java-weak-cipher","Hutool 5.8.27 wrapper selects a legacy cipher");
   if(call.getNameAsString().equals("aes"))return new Hit("java-weak-cipher","Hutool 5.8.27 selects bare AES with provider-default mode/padding; verify the effective provider and avoid relying on default ECB behavior");
  }
  return null;
 }
 static Hit creation(ObjectCreationExpr creation,ProjectContext context,CompilationUnit unit){
  if(context==null||!context.contracts.exact("cn.hutool:hutool-crypto","5.8.27"))return null;
  var owner=context.owner(creation,unit);String type=context.qualify(creation.getTypeAsString(),owner);if(!context.externalContractsAllowed(type))return null;
  if(type.equals("cn.hutool.crypto.symmetric.AES")){
   boolean defaults=creation.getArguments().size()<=1;
   boolean ecb=!creation.getArguments().isEmpty()&&("ECB".equals(ExpressionFacts.constantString(creation.getArgument(0)).orElse(""))||creation.getArgument(0).toString().endsWith("Mode.ECB"));
   if(defaults||ecb)return new Hit("java-weak-cipher",defaults?"Hutool AES constructor leaves mode/padding to provider defaults; effective ECB requires configuration review":"Hutool AES constructor explicitly selects ECB mode");
  }
  return null;
 }
}
