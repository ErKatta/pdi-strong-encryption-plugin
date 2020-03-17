package com.erkatta.pentaho.encryption.om;

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

import java.security.KeyPair;
import java.util.Base64;

/**
 * This class is a simple holder for a key pair (a public key and a private key). Both keys are intended to be in a Base64 encoded string format.
 * 
 * @author Marco Cattarin
 *
 */
public class Base64EncodedKeyPair {

	/** The public key as Base64 string. **/
	private final String publicKey;
	/** The private key as Base64 string. **/
	private final String privateKey;

	/**
	 * Initialize a new {@link Base64EncodedKeyPair}
	 * 
	 * @param keyPair a (public,private) key pai as {@link KeyPair}.
	 */
	public Base64EncodedKeyPair(KeyPair keyPair) {
		publicKey = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
		privateKey = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
	}

	/**
	 * Gets the public key.
	 * 
	 * @return the public key.
	 */
	public String getPublicKey() {
		return publicKey;
	}

	/**
	 * Gets the private key.
	 * 
	 * @return the private key.
	 */
	public String getPrivateKey() {
		return privateKey;
	}

	/**
	 * Returns a string representation of the {@link Base64EncodedKeyPair}.
	 * 
	 * @return a string representation of the {@link Base64EncodedKeyPair}.
	 */
	@Override
	public String toString() {
		return "Public key:"+publicKey+"\nPrivate key:"+privateKey;
	}

}
