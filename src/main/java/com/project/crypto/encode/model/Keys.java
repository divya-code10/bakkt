package com.project.crypto.encode.model;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Store information of public and private key
 * @author Divya
 *
 */
public class Keys {
	 PrivateKey privateKey;
	  PublicKey publicKey;
	  public Keys( PrivateKey privateKey, PublicKey publicKey){
		  this.privateKey = privateKey;
		  this.publicKey = publicKey;
	  }
	  public PublicKey getPublicKey(){
		  return publicKey;
	  }
     public PrivateKey getPrivateKey(){
		  return privateKey;
	  }
}
