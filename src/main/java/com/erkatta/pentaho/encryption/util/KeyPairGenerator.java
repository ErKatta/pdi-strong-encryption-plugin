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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

import com.erkatta.pentaho.encryption.om.Base64EncodedKeyPair;

/**
 * Utility class that can be used to generate the key file pair via command line.
 * 
 * @author Marco Cattarin
 *
 */
public class KeyPairGenerator {

	public static void main(String args[]) {
		Base64EncodedKeyPair keyPair = new RsaCryptoUtil().generateKeyPair();
		try {
			KeyPairGenerator.writeToFile("./public.key", keyPair.getPublicKey());
			KeyPairGenerator.writeToFile("./private.key", keyPair.getPrivateKey());
		} catch (IOException e) {
			throw new RuntimeException("Cannot generate keys.", e);
		}
	}

	/**
	 * Writes out on a file a key in a string format.
	 * 
	 * @param path the path of the file to write on disk
	 * @param key the key that has to be stored in the specified file
	 * @throws IOException if an I/O error occurs writing to or creating the file
	 */
	public static void writeToFile(String path, String key) throws IOException {
		Files.write(Paths.get(path), key.getBytes(StandardCharsets.UTF_8), StandardOpenOption.CREATE);
	}
}
