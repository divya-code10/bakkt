package com.project.crypto.encode;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EncoderDecoder {

	public static Logger logger = LogManager.getLogger(EncoderDecoder.class);
	public static void main(String[] args) throws Exception {
		String input = args[0];
		int n = Integer.parseInt(args[1]);
		int k = Integer.parseInt(args[2]);
		KeyProcessor processor = new KeyProcessor();
		//generates public and private keys and store private key in n shards
		processor.processKeys(n, k);
		byte[] encoded = processor.encrypt(input);
		//takes input of encoded
		String decoded = processor.decrypt(new int[] {1,5}, encoded);
		System.out.println(" decoded: "+decoded+" input: "+input);
		processor.moveFiles();
	}
}
