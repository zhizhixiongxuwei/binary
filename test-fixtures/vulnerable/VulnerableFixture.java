import java.io.File;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.sql.Statement;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509TrustManager;
import javax.script.ScriptEngine;
import javax.xml.parsers.DocumentBuilderFactory;

public final class VulnerableFixture implements HostnameVerifier, X509TrustManager {
    public boolean verify(String host, SSLSession session) { return true; }
    public void checkClientTrusted(X509Certificate[] chain, String auth) {}
    public void checkServerTrusted(X509Certificate[] chain, String auth) {}
    public X509Certificate[] getAcceptedIssuers() { return null; }

    public void analyze(String user, InputStream raw) throws Exception {
        MessageDigest.getInstance("MD5");
        Cipher.getInstance("AES/ECB/PKCS5Padding");
        SSLContext.getInstance("TLSv1.1");
        new SecretKeySpec("embedded-key".getBytes("UTF-8"), "AES");

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://xml.org/sax/features/external-general-entities", true);
        new ObjectInputStream(raw).readObject();

        Statement statement = null;
        statement.executeQuery("SELECT * FROM users WHERE name='" + user + "'");
        Runtime.getRuntime().exec(user);
        new ProcessBuilder(user);

        ScriptEngine engine = null;
        engine.eval(user);
        File file = null;
        file.setWritable(true, false);
        Cookie cookie = null;
        cookie.setSecure(false);
    }

    static final class Cookie {
        void setSecure(boolean secure) {}
    }
}
