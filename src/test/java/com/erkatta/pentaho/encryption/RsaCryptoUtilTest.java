package com.erkatta.pentaho.encryption;

/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Lesser Public License for more details.
 * 
 * You should have received a copy of the GNU General Lesser Public
 * License along with this program.  If not, see
 * <http://www.gnu.org/licenses/lgpl-2.1.html>.
 */

import org.assertj.core.api.Assertions;
import org.junit.Test;

import com.erkatta.pentaho.encryption.om.Base64EncodedKeyPair;
import com.erkatta.pentaho.encryption.util.AsymmetricCryptoUtil;
import com.erkatta.pentaho.encryption.util.RsaCryptoUtil;

/**
 * Test for the {@link RsaCryptoUtil}} class.
 * 
 * @author Marco Cattarin
 *
 */
public class RsaCryptoUtilTest {

	private static final String PLAIN_TEXT_ASCII = "This is just a text sequence";
	private static final String PLAIN_TEXT_UTF8 = "This is just a text sequence with  some UTF-8 characters: àèìòù";
	private static final String PLAIN_TEXT_MORE_THAN_256_BYTES = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed gravida vulputate eleifend. Vestibulum imperdiet purus sed diam vestibulum, a condimentum ligula elementum. Maecenas a volutpat dui. Suspendisse faucibus nunc at tortor vestibulum, quis volutpat. Fail!";
	
	/** The RSA cryptographic utility to test. **/
	private AsymmetricCryptoUtil cryptoUtil = new RsaCryptoUtil();

	/**
	 * Test the transcryption using a string made of ASCII characters only.
	 */
	@Test
	public void testTranscryptionAscii() {
		testTranscryption(PLAIN_TEXT_ASCII);
	}

	/**
	 * Test the transcryption using a string made of ASCII and UTF-8 characters.
	 */
	@Test
	public void testTranscryptionUtf8() {
		testTranscryption(PLAIN_TEXT_UTF8);
	}

	/**
	 * The RSA algorithm can only encrypt data that has a maximum byte length of the
	 * RSA key length in bits divided with eight minus eleven padding bytes, i.e.
	 * number of maximum bytes = key length in bits / 8 - 11 In this case, the key
	 * length 2048 bytes data is 245 bytes (256 excluding padding).
	 */
	@Test(expected = RuntimeException.class)
	public void testTranscryptionLongerThan256Bytes() {
		testTranscryption(PLAIN_TEXT_MORE_THAN_256_BYTES);
	}

	/**
	 * Tests the encoding and decoding capabilities of the RSA cryptographic
	 * utility.
	 * 
	 * @param plainText the text to encrypt and decrypt.
	 */
	private void testTranscryption(String plainText) {
		Base64EncodedKeyPair keyPair = cryptoUtil.generateKeyPair();
		String ecryptedData = cryptoUtil.encrypt(plainText, keyPair.getPublicKey());
		String decryptedData = cryptoUtil.decrypt(ecryptedData, keyPair.getPrivateKey());
		Assertions.assertThat(decryptedData).isEqualTo(plainText);
	}
}
