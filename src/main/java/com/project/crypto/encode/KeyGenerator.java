package com.project.crypto.encode;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import com.project.crypto.encode.model.Keys;

public class KeyGenerator {
  
   private static KeyGenerator instance;
   /**
    * generates public private key based on algo provided in input
    * @param algo
 * @throws Exception 
    */
   
   public static KeyGenerator getInstance() {
	   if(instance == null) {
		   synchronized(KeyGenerator.class) {
			   if(instance == null) {
				   instance = new KeyGenerator();
			   }
		   }
	   }
	   return instance;
   }
   
   /**
    * generate public private key based on algo provided
    * @param algo
    * @return
    * @throws Exception
    */
   Keys generateKeys(String algo ) throws Exception {
	  
		   KeyPairGenerator keyGen;
		   Keys keys = null;
		   try {
			   keyGen = KeyPairGenerator.getInstance(algo);
			   keyGen.initialize(2048);
			   KeyPair pair = keyGen.generateKeyPair();
			   keys = new Keys(pair.getPrivate(),pair.getPublic());
		   } catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			throw new SecurityException(algo+" not supported",e);
		  }
		   return keys;
	  
	};

 
}
