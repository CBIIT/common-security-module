/*L
 *  Copyright Ekagra Software Technologies Ltd.
 *  Copyright SAIC, SAIC-Frederick
 *
 *  Distributed under the OSI-approved BSD 3-Clause License.
 *  See http://ncip.github.com/common-security-module/LICENSE.txt for details.
 */

/*
 * Created on Mar 7, 2005
 *
 * TODO To change the template for this generated file go to
 * Window - Preferences - Java - Code Style - Code Templates
 */
package com.ekagra.test;


import java.util.concurrent.*;
import java.util.Properties;
import java.util.Random;

/**
 * @author kumarvi
 *
 * TODO To change the template for this generated type comment go to
 * Window - Preferences - Java - Code Style - Code Templates
 */
public class TestRunner {

	static{
		try{
		Properties p = System.getProperties();
		p.setProperty("gov.nih.nci.security.configFile","C:/securityConfig/ApplicationsecurityConfig.xml");
		}catch(Exception ex){
			ex.printStackTrace();
		}
	}
	public void runTest(){
		Random random = new Random();
		/**
		 * Creating a pool of 50 threads
		 */
		ExecutorService executor = 
            Executors.newFixedThreadPool(150);
		int waitTime = 500;
		/**
		 * Sending 150 user requests to serve
		 */
		for (int i=0; i<1001; i++) {
	         String name = "UserSession " + i;
	         int time = random.nextInt(10);
	         waitTime += time;
	         Runnable runner = new UserSession(name, time);
	         System.out.println("Adding: " + name + " / " + time);
	         executor.execute(runner);
	       }
		try {
	         //Thread.sleep(waitTime);
			Thread.sleep(500000);
	         executor.shutdown();
	         executor.awaitTermination
	                 (waitTime, TimeUnit.MILLISECONDS);
	       } catch (InterruptedException ignored) {
	       }
	       System.exit(0);
	}
	public static void main(String[] args) {
		TestRunner tr = new TestRunner();
		tr.runTest();
	}
}
