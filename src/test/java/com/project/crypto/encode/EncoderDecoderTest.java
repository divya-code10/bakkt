package com.project.crypto.encode;

import static org.junit.Assert.assertTrue;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;


public class EncoderDecoderTest {

	@Rule
	public TemporaryFolder folder= new TemporaryFolder();
	
	@Test
	public void test() throws Exception {
		String input = "test";
		KeyProcessor processor = new KeyProcessor();
		int n = 5,k = 2;
		processor.processKeys(n, k);
		byte[] encoded = processor.encrypt(input);
		String decoded = processor.decrypt(new int[] {2,5}, encoded);
		System.out.println(decoded);
		assertTrue(input.equals(decoded));
		processor.moveFiles();
	}

}
