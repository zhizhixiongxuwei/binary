package org.filetools.archive;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import javax.crypto.Cipher;

public final class ArchiveTool {
   private ArchiveTool() {
   }

   public static byte[] passwordDigest(String password) throws Exception {
      return MessageDigest.getInstance("MD5").digest(password.getBytes(StandardCharsets.UTF_8));
   }

   public static Cipher createCipher() throws Exception {
      return Cipher.getInstance("DES");
   }

   public static void main(String[] args) {
      System.out.println("Archive Toolkit 1.3.2");
      System.out.println("Usage: java -jar archive-toolkit-1.3.2.jar");
   }
}
