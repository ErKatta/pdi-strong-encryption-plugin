package com.erkatta.pentaho.encryption.util;

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

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.erkatta.pentaho.encryption.om.Base64EncodedKeyPair;

/**
 * The cryptographic utility class based on RSA {@link https://en.wikipedia.org/wiki/RSA_(cryptosystem)}
 * 
 * @author Marco Cattarin
 *
 */
public final class RsaCryptoUtil implements AsymmetricCryptoUtil {

	/** The key factory used to convert keys into key specifications. **/
	private KeyFactory rsaKeyFactory;
	
	/** Provides the functionality of a cryptographic cipher for encryption and decryption. */
	private Cipher cipher;

	/**
	 * Instantiates a new RSA crypto utility.
	 */
	public RsaCryptoUtil() {
		try {
			rsaKeyFactory = KeyFactory.getInstance("RSA");
			cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			throw new RuntimeException("Cannot create a new instance of CryptoUtil.", e);
		}

	}

	/**
	 * Encrypts data.
	 * 
	 * @param data the data to encrypt as byte array.
	 * @param publicKey the public key to use to encode the data as Base64 encoded string.
	 * @return the encrypted data as byte array.
	 */
	@Override
	public byte[] encrypt(byte[] data, String publicKey) {
		return encrypt(data, getPublicKey(publicKey));
	}

    /**
	 * Encrypts data.
	 * 
	 * @param data the data to encrypt as string.
	 * @param publicKey the public key to use to encode the data as Base64 encoded string.
	 * @return the encrypted data as string.
	 */
	@Override
	public String encrypt(String data, String publicKey) {
		return Base64.getEncoder().encodeToString(encrypt(data.getBytes(StandardCharsets.UTF_8), publicKey));
	}

	/**
	 * Decrypts data.
	 * 
	 * @param data the data to decrypt as byte array.
	 * @param privateKey the private key to use to decode the data as Base64 encoded string.
	 * @return the decrypted data as byte array.
	 */
	@Override
	public byte[] decrypt(byte[] data, String privateKey) {
		return decrypt(data, getPrivateKey(privateKey));
	}

	/**
	 * Decrypts data.
	 * 
	 * @param data the data to decrypt as string.
	 * @param privateKey the private key to use to decode the data as Base64 encoded string.
	 * @return the decrypted data as string.
	 */
	@Override
	public String decrypt(String data, String privateKey) {
		return new String(decrypt(Base64.getDecoder().decode(data.getBytes(StandardCharsets.UTF_8)), privateKey),
				StandardCharsets.UTF_8);
	}

    /**
     * Generates a (public,private) key pair.
     * 
     * @return a pair of Base64 encoded keys.
     */
	@Override
	public Base64EncodedKeyPair generateKeyPair() {
		try {
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(2048);
			return new Base64EncodedKeyPair(keyGen.generateKeyPair());
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Cannot generate key pair.", e);
		}

	}

	/**
	 * Gets a {@link PublicKey} from its Base64 encoded form.
	 *
	 * @param base64PublicKey the public key encoded as Base64 string.
	 * @return the public key as {@link PublicKey}.
	 */
	protected PublicKey getPublicKey(String base64PublicKey) {
		PublicKey publicKey = null;
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(
				Base64.getDecoder().decode(base64PublicKey.getBytes(StandardCharsets.UTF_8)));
		try {
			publicKey = rsaKeyFactory.generatePublic(keySpec);
		} catch (InvalidKeySpecException e) {
			throw new RuntimeException("Cannot generate the public key.", e);
		}
		return publicKey;
	}

	/**
	 * Gets a {@link PrivateKey} from its Base64 encoded form.
	 *
	 * @param base64PrivateKey the private key encoded as Base64 string.
	 * @return the private key as {@link PrivateKey}.
	 */
	protected PrivateKey getPrivateKey(String base64PrivateKey) {
		PrivateKey privateKey = null;
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(
				Base64.getDecoder().decode(base64PrivateKey.getBytes(StandardCharsets.UTF_8)));
		try {
			privateKey = rsaKeyFactory.generatePrivate(keySpec);
		} catch (InvalidKeySpecException e) {
			throw new RuntimeException("Cannot generate the public key.", e);
		}
		return privateKey;

	}

	/**
	 * Encrypts data.
	 * 
	 * @param data the data to encrypt as byte array.
	 * @param publicKey the public key to use to encode the data as {@link PublicKey}.
	 * @return the encrypted data as byte array.
	 */
	private byte[] encrypt(byte[] data, PublicKey publicKey) {
		synchronized (cipher) {
			try {
				cipher.init(Cipher.ENCRYPT_MODE, publicKey);
				return cipher.doFinal(data);
			} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
				throw new RuntimeException("Cannot encrypt data.", e);
			}

		}
	}

	/**
	 * Decrypts data.
	 * 
	 * @param data the data to decrypt as byte array.
	 * @param privateKey the private key to use to decode the data as {@link PrivateKey}.
	 * @return the decrypted data as byte array.
	 */
	private byte[] decrypt(byte[] data, PrivateKey privateKey) {
		synchronized (cipher) {
			try {
				cipher.init(Cipher.DECRYPT_MODE, privateKey);
				return cipher.doFinal(data);
			} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
				throw new RuntimeException("Cannot decrypt data.", e);
			}

		}
	}

}
