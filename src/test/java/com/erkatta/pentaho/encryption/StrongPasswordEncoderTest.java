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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

import org.assertj.core.api.Assertions;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.ProvideSystemProperty;
import org.pentaho.di.core.KettleClientEnvironment;
import org.pentaho.di.core.encryption.Encr;
import org.pentaho.di.core.encryption.KettleTwoWayPasswordEncoder;
import org.pentaho.di.core.exception.KettleException;

import com.erkatta.pentaho.encryption.StrongPasswordEncoder;
import com.erkatta.pentaho.encryption.om.Base64EncodedKeyPair;
import com.erkatta.pentaho.encryption.util.KeyPairGenerator;
import com.erkatta.pentaho.encryption.util.RsaCryptoUtil;

/**
 * Test for the {@link StrongPasswordEncoderTest}} class.
 * 
 * @author Marco Cattarin
 *
 */
public class StrongPasswordEncoderTest {
	private static final String PUBLIC_KEY_FILE_LOCATION = "/tmp/public.key";
	private static final String PRIVATE_KEY_FILE_LOCATION = "/tmp/private.key";
	private static final String KETTLE_OBFUSCATED_PASSWORD = "6a757374616e6f60d8eddcab0bd39780bb18bd63c99dbdde";
	private static final String KETTLE_PLAIN_TEXT_PASSWORD = "justanobfuscatedpassword";
	private static final String PLAIN_TEXT_PASSWORD = "justatestpassword";
	private static final String PLAIN_TEXT_PASSWORD_WITH_VARIABLES = "justatestpasswordwith${VARIABLES}";

	/** The RSA cryptographic utility used to generate the test key pair. **/
	private static final RsaCryptoUtil CRYPTOUTIL = new RsaCryptoUtil();

	/**
	 * This rule allow us to set system properties at runtime, cleaning them after
	 * the test execution.
	 **/
	@ClassRule
	public static final ProvideSystemProperty properties = new ProvideSystemProperty(
			"KETTLE_STRONG_PASSWORD_ENCODER_PUBKEY_PATH", "/tmp/").and("KETTLE_STRONG_PASSWORD_ENCODER_PRIVKEY_PATH",
					"/tmp/");

	/**
	 * Sets up the test environment.
	 */
	@BeforeClass
	public static void setUp() {
		try {
			Files.deleteIfExists(Paths.get(PUBLIC_KEY_FILE_LOCATION));
			Files.deleteIfExists(Paths.get(PRIVATE_KEY_FILE_LOCATION));
			Base64EncodedKeyPair keyPair = CRYPTOUTIL.generateKeyPair();
			KeyPairGenerator.writeToFile(PUBLIC_KEY_FILE_LOCATION, keyPair.getPublicKey());
			KeyPairGenerator.writeToFile(PRIVATE_KEY_FILE_LOCATION, keyPair.getPrivateKey());
			initKettleEncr();
		} catch (KettleException | IOException e) {
			throw new RuntimeException("Cannot initialize test.", e);
		}
	}

	/**
	 * Test password encryption and decryption.
	 */
	@Test
	public void testTranscryption() {
		Assertions
				.assertThat(Encr.decryptPasswordOptionallyEncrypted(
						StrongPasswordEncoder.PASSWORD_ENCRYPTED_PREFIX + Encr.encryptPassword(PLAIN_TEXT_PASSWORD)))
				.isEqualTo(PLAIN_TEXT_PASSWORD);
		Assertions.assertThat(Encr.decryptPassword(Encr.encryptPasswordIfNotUsingVariables(PLAIN_TEXT_PASSWORD)))
				.isEqualTo(PLAIN_TEXT_PASSWORD);
	}

	/**
	 * Tests prefix usage in the encryption process.
	 */
	@Test
	public void testEncryptionWithPrefix() {
		Assertions.assertThat(Encr.encryptPasswordIfNotUsingVariables(PLAIN_TEXT_PASSWORD))
				.startsWith(StrongPasswordEncoder.PASSWORD_ENCRYPTED_PREFIX);
		Assertions.assertThat(Encr.encryptPasswordIfNotUsingVariables(PLAIN_TEXT_PASSWORD_WITH_VARIABLES))
				.doesNotStartWith(StrongPasswordEncoder.PASSWORD_ENCRYPTED_PREFIX)
				.isEqualTo(PLAIN_TEXT_PASSWORD_WITH_VARIABLES);
	}

	/**
	 * Tests the default kettle obfuscation decryption support.
	 */
	@Test
	public void testDecryptionKettleObfuscationSupport() {
		Assertions
				.assertThat(Encr.decryptPasswordOptionallyEncrypted(
						KettleTwoWayPasswordEncoder.PASSWORD_ENCRYPTED_PREFIX + KETTLE_OBFUSCATED_PASSWORD))
				.isEqualTo(KETTLE_PLAIN_TEXT_PASSWORD);
		Assertions.assertThat(Encr.decryptPassword(KETTLE_OBFUSCATED_PASSWORD)).isEqualTo(KETTLE_PLAIN_TEXT_PASSWORD);
	}

	/**
	 * Initializes the Kettle Encr class.
	 * 
	 * @throws KettleException in case of errors during the environment
	 *                         initialization.
	 * 
	 */
	private static void initKettleEncr() throws KettleException {
		KettleClientEnvironment.init();
		Encr.init("SPE");
	}

}
