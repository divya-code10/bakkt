package com.project.crypto.encode;

import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class KeyEncoder {
	
	String key = "secret";
	private final byte[] ivBytes = new byte[] { 32, 87, -14, 25, 78, -104, 98, 40 };
;
	public byte[] encrypt(byte[] originalData) {
	    Cipher cipher = null;
	    try {
	        cipher = Cipher.getInstance("Blowfish/CBC/PKCS5Padding");
	        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "Blowfish");
	        IvParameterSpec iv = new IvParameterSpec(ivBytes);
	        cipher.init(Cipher.ENCRYPT_MODE, keySpec,iv);
	        return cipher.doFinal(originalData);
	    } catch (GeneralSecurityException e) {
	        // seems there isn't a standard exception hierarchy for properties, so go with just RuntimeException
	        throw new RuntimeException(e);
	    }
	}

	
	/**
	 * Decrypts the given data.
	 *
	 * @param encryptedData
	 *          Data to decrypt.
	 * @return Decrypted data.
	 */
	public byte[] decrypt(byte[] encryptedData) {
	    try {
	        Cipher cipher = Cipher.getInstance("Blowfish/CBC/PKCS5Padding");
	        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "Blowfish");
	        IvParameterSpec iv = new IvParameterSpec(ivBytes);
	        cipher.init(Cipher.DECRYPT_MODE, keySpec,iv);
	        return cipher.doFinal(encryptedData);
	    } catch (GeneralSecurityException e) {
	        // seems there isn't a standard exception hierarchy for properties, so go with just RuntimeException
	        throw new RuntimeException(e);
	    }
	}

}
