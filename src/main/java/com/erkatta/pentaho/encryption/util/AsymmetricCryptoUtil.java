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

import com.erkatta.pentaho.encryption.om.Base64EncodedKeyPair;

/**
 * A generic interface that represent a cryptographic utility that relies on asymmetric keys cryptography.
 * 
 * @author Marco Cattarin
 *
 */
public interface AsymmetricCryptoUtil {
	
	/**
	 * Encrypts data.
	 * 
	 * @param data the data to encrypt as byte array.
	 * @param publicKey the public key to use to encode the data as Base64 encoded string.
	 * @return the encrypted data as byte array.
	 */
    public byte[] encrypt(byte[] data, String publicKey);
    
    /**
	 * Encrypts data.
	 * 
	 * @param data the data to encrypt as string.
	 * @param publicKey the public key to use to encode the data as Base64 encoded string.
	 * @return the encrypted data as string.
	 */
    public String encrypt(String data, String publicKey);

	/**
	 * Decrypts data.
	 * 
	 * @param data the data to decrypt as byte array.
	 * @param privateKey the private key to use to decode the data as Base64 encoded string.
	 * @return the decrypted data as byte array.
	 */
    public byte[] decrypt(byte[] data, String privateKey);

	/**
	 * Decrypts data.
	 * 
	 * @param data the data to decrypt as string.
	 * @param privateKey the private key to use to decode the data as Base64 encoded string.
	 * @return the decrypted data as string.
	 */
    public String decrypt(String data, String privateKey);
    
    /**
     * Generates a (public,private) key pair.
     * 
     * @return a pair of Base64 encoded keys.
     */
    public Base64EncodedKeyPair generateKeyPair();
}
