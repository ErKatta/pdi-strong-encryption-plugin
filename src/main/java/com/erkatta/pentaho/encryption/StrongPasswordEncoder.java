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
import java.util.ArrayList;
import java.util.List;

import org.pentaho.di.core.encryption.KettleTwoWayPasswordEncoder;
import org.pentaho.di.core.encryption.TwoWayPasswordEncoderInterface;
import org.pentaho.di.core.encryption.TwoWayPasswordEncoderPlugin;
import org.pentaho.di.core.exception.KettleException;
import org.pentaho.di.core.util.EnvUtil;
import org.pentaho.di.core.util.StringUtil;

import com.erkatta.pentaho.encryption.util.AsymmetricCryptoUtil;
import com.erkatta.pentaho.encryption.util.RsaCryptoUtil;

/**
 * This class handles a stronger encryption of passwords than the default one
 * provided by Kettle.
 *
 * @author Marco Cattarin
 *
 */
@TwoWayPasswordEncoderPlugin(id = "SPE", name = "StrongPasswordEncoder")
public class StrongPasswordEncoder implements TwoWayPasswordEncoderInterface {

	/** The name of the system property that carries the public key file name. **/
	private static final String PUBLIC_KEY_FILENAME_KEY = "KETTLE_STRONG_PASSWORD_ENCODED_PUBKEY_FILENAME";
	/** The name of the system property that carries the private key file name. **/
	private static final String PRIVATE_KEY_FILENAME_KEY = "KETTLE_STRONG_PASSWORD_ENCODED_PRIVKEY_FILENAME";
	/** The name of the system property that carries the public key file path. **/
	private static final String PUBLIC_KEY_PATH_KEY = "KETTLE_STRONG_PASSWORD_ENCODED_PUBKEY_PATH";
	/** The name of the system property that carries the private key file path. **/
	private static final String PRIVATE_KEY_PATH_KEY = "KETTLE_STRONG_PASSWORD_ENCODED_PRIVKEY_PATH";

	/** The default public key file name. **/
	private static final String PUBLIC_KEY_FILENAME_DEFAUT = "public.key";
	/** The default private key file name. **/
	private static final String PRIVATE_KEY_FILENAME_DEFAULT = "private.key";
	/** The default public key file path. **/
	private static final String PUBLIC_KEY_PATH_DEFAUT = "./";
	/** The default private key file path. **/
	private static final String PRIVATE_KEY_PATH_DEFAULT = "./";

	/**
	 * The word that is put before a password to indicate an encrypted form. If this
	 * word is not present, the password is considered to be NOT encrypted.
	 */
	public static final String PASSWORD_ENCRYPTED_PREFIX = "SPEncrypted ";

	/** The cryptographic utility used to encode and decode passwords. **/
	private AsymmetricCryptoUtil cryptoUtil;

	/** The public key file name. **/
	private String publicKeyFilename;
	/** The private key file name. **/
	private String privateKeyFilename;
	/** The public key file path. **/
	private String publicKeyPath;
	/** The private key file path. **/
	private String privateKeyPath;

	/** The public key in a Base64 encoded form. **/
	private String publicKey = null;
	/** The private key in a Base64 encoded form. **/
	private String privateKey = null;

	/**
	 * Creates a new instance of {@link StrongPasswordEncoder}
	 */
	public StrongPasswordEncoder() {
		publicKeyFilename = EnvUtil.getSystemProperty(PUBLIC_KEY_FILENAME_KEY, PUBLIC_KEY_FILENAME_DEFAUT);
		privateKeyFilename = EnvUtil.getSystemProperty(PRIVATE_KEY_FILENAME_KEY, PRIVATE_KEY_FILENAME_DEFAULT);
		publicKeyPath = EnvUtil.getSystemProperty(PUBLIC_KEY_PATH_KEY, PUBLIC_KEY_PATH_DEFAUT);
		privateKeyPath = EnvUtil.getSystemProperty(PRIVATE_KEY_PATH_KEY, PRIVATE_KEY_PATH_DEFAULT);
		cryptoUtil = new RsaCryptoUtil();
	}

	/**
	 * Initializes the password encoder by loading key details from the environment
	 * (kettle.properties or system settings).
	 * 
	 * @throws KettleException
	 */
	@Override
	public void init() throws KettleException {
		publicKey = getPublicKeyValue();
		privateKey = getPrivateKeyValue();
	}

	/**
	 * Encodes the raw password, include a prefix indicating the type of encryption
	 * used.
	 * 
	 * @param password The password to encode
	 * @return The encoded password string
	 */
	@Override
	public String encode(String rawPassword) {
		return encode(rawPassword, true);
	}

	/**
	 * Encodes a password.
	 * 
	 * @param password      The password to encode
	 * @param includePrefix True if a prefix needs to be encoded
	 * @return The encoded password string
	 */
	@Override
	public String encode(String rawPassword, boolean includePrefix) {
		if (includePrefix) {
			return encryptPasswordIfNotUsingVariablesInternal(rawPassword);
		} else {
			return encrypt(rawPassword);
		}
	}

	/**
	 * Decodes a password which does NOT have a prefix attached.
	 * 
	 * @param encodedPassword The encoded password without a prefix
	 * @return The decoded password string
	 */
	@Override
	public String decode(String encodedPassword) {
		if (encodedPassword != null && encodedPassword.startsWith(PASSWORD_ENCRYPTED_PREFIX)) {
			encodedPassword = encodedPassword.substring(PASSWORD_ENCRYPTED_PREFIX.length());
		} else if (encodedPassword != null
				&& encodedPassword.startsWith(KettleTwoWayPasswordEncoder.PASSWORD_ENCRYPTED_PREFIX)) {
			encodedPassword = encodedPassword.substring(KettleTwoWayPasswordEncoder.PASSWORD_ENCRYPTED_PREFIX.length());

		}
		try {
			return decrypt(encodedPassword);
		} catch (Exception e) {
			// If the decription has failed fallback to the default KettleTwoWayPasswordEncoder. 
			// Using the deprecated method to support default obfuscation without messing up
			// with a new instance of Encr object.
			return KettleTwoWayPasswordEncoder.decryptPassword(encodedPassword);
		}
	}

	/**
	 * Decodes a password.
	 * 
	 * @param encodedPassword     The encoded password with or without a prefix
	 * @param optionallyEncrypted Set to true if the password is optionally
	 *                            encrypted (indicated by a prefix).
	 * @return The decoded password string
	 */
	@Override
	public String decode(String encodedPassword, boolean optionallyEncrypted) {

		if (encodedPassword == null) {
			return null;
		}

		if (optionallyEncrypted) {

			if (encodedPassword.startsWith(PASSWORD_ENCRYPTED_PREFIX)) {
				encodedPassword = encodedPassword.substring(PASSWORD_ENCRYPTED_PREFIX.length());
				return decrypt(encodedPassword);
			} else if (encodedPassword.startsWith(KettleTwoWayPasswordEncoder.PASSWORD_ENCRYPTED_PREFIX)) {
				// Using the deprecated method to support default obfuscation without messing up
				// with a new instance of Encr object.
				return KettleTwoWayPasswordEncoder.decryptPasswordOptionallyEncrypted(encodedPassword);
			} else {
				return encodedPassword;
			}
		} else {
			return decrypt(encodedPassword);
		}
	}

	/**
	 * Returns the password prefixes supported by this password encoder.
	 * 
	 * @return The prefixes to the encoded passwords which this password encoder
	 *         supports.
	 */
	@Override
	public String[] getPrefixes() {
		return new String[] { PASSWORD_ENCRYPTED_PREFIX, KettleTwoWayPasswordEncoder.PASSWORD_ENCRYPTED_PREFIX };
	}

	/**
	 * Gets the Base64 value of the private key.
	 * 
	 * @return the Base64 value of the private key.
	 */
	private String getPrivateKeyValue() {
		try {
			return new String(Files.readAllBytes(Paths.get(privateKeyPath + privateKeyFilename)),StandardCharsets.UTF_8);
		} catch (IOException e) {
			throw new RuntimeException("Cannot load private key.", e);
		}

	}

	/**
	 * Gets the Base64 value of the public key.
	 * 
	 * @return the Base64 value of the public key.
	 */
	private String getPublicKeyValue() {
		try {
			return new String(Files.readAllBytes(Paths.get(publicKeyPath + publicKeyFilename)),StandardCharsets.UTF_8);
		} catch (IOException e) {
			throw new RuntimeException("Cannot load public key.", e);
		}

	}

	/**
	 * Decrypts an encrypted password.
	 * 
	 * @param encryptedPassword the password to decrypt.
	 * @return the password in plain text.
	 */
	private String decrypt(String encryptedPassword) {
		return cryptoUtil.decrypt(encryptedPassword, privateKey);
	}

	/**
	 * Encrypts a password.
	 * 
	 * @param password the password to encrypt in plain text.
	 * @return the encrypted password.
	 */
	private String encrypt(String password) {
		return cryptoUtil.encrypt(password, publicKey);
	}

	/**
	 * Encrypt the password, but only if the password doesn't contain any variables.
	 *
	 * @param password The password to encrypt
	 * @return The encrypted password or the
	 */
	private final String encryptPasswordIfNotUsingVariablesInternal(String password) {
		String encrPassword = "";
		List<String> varList = new ArrayList<>();
		StringUtil.getUsedVariables(password, varList, true);
		if (varList.isEmpty()) {
			encrPassword = PASSWORD_ENCRYPTED_PREFIX + encrypt(password);
		} else {
			encrPassword = password;
		}

		return encrPassword;
	}

}
