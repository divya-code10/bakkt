package com.project.crypto.encode;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.Cipher;

import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.codahale.shamir.Scheme;
import com.project.crypto.encode.model.Keys;

/**
 * 
 * @author Divya Generate keys using specified algorith from Key Generator
 *         Process public key to store in file private key is processed to be
 *         sharded across n node using Shamir's algo
 *
 */
public class KeyProcessor {

	private static Logger logger = LogManager.getLogger(KeyProcessor.class);

	KeyGenerator keyGen = KeyGenerator.getInstance();
	List<File> privateFiles = new ArrayList<File>();
	File publicFile = null;
	Scheme scheme = null;
	KeyEncoder keyEncoder = new KeyEncoder();

	/**
	 * we will assume total n nodes of which 2 are needed to reconstruct key
	 * 
	 * @param input
	 * @param n     total no of shard
	 * 
	 * @param k     min shards that will generate correct content
	 * @throws Exception
	 */

	public void processKeys(int n, int k) throws Exception {
		// Can take algo as input parameter or read from file
		logger.info("Public private key generation start");
		Keys keys = keyGen.generateKeys("RSA");
		logger.info("Public private key generation end");
		
		//Shamir's secret sharing algo used for private key start
		scheme = new Scheme(new SecureRandom(), n, k);

		// convert input to byte array
		 byte[] privateKeyByteArray = keys.getPrivateKey().getEncoded();

		//encode private key array
		//privateKeyByteArray = keyEncoder.encrypt(privateKeyByteArray);
		// split private key to multiple shards
		final Map<Integer, byte[]> parts = scheme.split(privateKeyByteArray);
		
		//Shamir' algo end by creating multiple shards for private key

		// create directory and files for storing public keys and private keys
		createDirectory(n);

		// write public key to file

		logger.info("Public  key witten to "+publicFile.getAbsolutePath());
		storeToFile(keys.getPublicKey().getEncoded(), publicFile);

		// write private key separated to n files
		for (int i = 1; i <= privateFiles.size(); i++) {
			storeToFile(parts.get(i), privateFiles.get(i - 1));
			logger.info("Private  key witten to "+privateFiles.get(i-1).getAbsolutePath());
		}

	}

	/**
	 * reconstruct input using private key
	 * 
	 * @param input
	 * @param shards
	 * @return
	 * @throws Exception
	 */
	public String decrypt(int[] shards, byte[] encoded) throws Exception {
		logger.info("Decryption started using private file");
		
		 byte[] recovered = scheme.join(recoverPrivateContent(shards));
		//decrypt bytes of private key
		// recovered = keyEncoder.decrypt(recovered);
		logger.info("Private key recovered using shards: "+Arrays.toString(shards));
		PrivateKey privateKey = readPrivateKey(recovered);
		// reconstruct private key from bytes
		Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] res = cipher.doFinal(encoded);
		logger.info("Decryption completed");
		return new String(res);

	}

	/**
	 * encrypts input using public key first create public key from public file and
	 * then encrypt it
	 * 
	 * @param input
	 * @return
	 */

	public byte[] encrypt(String input) throws Exception {
		logger.info("Encryption started using public file for input: "+input);
		String root = "keys/";
		PublicKey publicKey = readPublicKey(root + "Public.TXT");
		Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		logger.info("Encryption completed for input: "+input);
		return cipher.doFinal(input.getBytes());

	}

	public byte[] readFileBytes(String filename) throws IOException {
		Path path = Paths.get(filename);
		byte[] out =  Files.readAllBytes(path);
		// out =  keyEncoder.decrypt(out);
		 return out;
	}

	public PublicKey readPublicKey(String filename)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(readFileBytes(filename));
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		return keyFactory.generatePublic(publicSpec);
	}

	public PrivateKey readPrivateKey(byte[] bytes)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(bytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		return keyFactory.generatePrivate(keySpec);
	}

	// recover private content using shard nos as input
	Map<Integer, byte[]> recoverPrivateContent(int[] input) {
		Map<Integer, byte[]> parts = new HashMap<Integer, byte[]>();
		String root = "keys/";
		for (int i : input) {
			// read private file data
			Path path = Paths.get(root + "Shard[" + i + "].TXT");
			try {
				byte[] data = Files.readAllBytes(path);
				parts.put(i, data);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				logger.error("Error while reading file " + path);
				throw new SecurityException("Error while reading file " + path, e);
			}
		}
		return parts;
	}

	/**
	 * writes bytes to particular file
	 */
	/**
	 * created public and private files k is no of private files that has to be
	 * created
	 */
	public void createDirectory(int n) {
		String path = "keys";
		try {

			File dir = new File(path);
			dir.mkdir();
			publicFile = new File(dir, "Public.TXT");
			publicFile.createNewFile();
			for (int i = 1; i <= n; i++) {
				File privateFile = new File(dir, "/Shard[" + i + "].TXT");
				privateFile.createNewFile();
				privateFiles.add(privateFile);
			}
			logger.debug("Key files created successfully");

		} catch (IOException e) {
			logger.error("Failed to create files for keys");
			throw new SecurityException("Failed to create files for keys", e);
		}

	}

	/**
	 * Store all files from keys directory to testRun directory
	 * @throws IOException 
	 */
	public void moveFiles() throws IOException {
		FileUtils.deleteDirectory(new File("testRun"));
		File directory = new File("keys");
		directory.renameTo(new File("testRun"));

	}

	public void storeToFile(byte[] input, File file) {
		//input = keyEncoder.encrypt(input);
		Path path = Paths.get(file.getAbsolutePath());
		try {
			Files.write(path, input);
		} catch (IOException e) {
			logger.error("Error in writing to path " + file.getAbsolutePath());
			throw new SecurityException("Failed to write to file " + file.getAbsolutePath(), e);
		}
	}
}
