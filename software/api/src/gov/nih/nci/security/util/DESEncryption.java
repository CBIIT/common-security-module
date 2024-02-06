/*L
 *  Copyright Ekagra Software Technologies Ltd.
 *  Copyright SAIC, SAIC-Frederick
 *
 *  Distributed under the OSI-approved BSD 3-Clause License.
 *  See http://ncip.github.com/common-security-module/LICENSE.txt for details.
 */

package gov.nih.nci.security.util;

import gov.nih.nci.security.util.StringEncrypter.EncryptionException;

import java.io.UnsupportedEncodingException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;

import java.util.Base64;

public class DESEncryption implements Encryption {
	public static final String DESEDE_ENCRYPTION_SCHEME = "DESede";

	public static final String DES_ENCRYPTION_SCHEME = "DES";

	private static KeySpec keySpec;

	private static SecretKeyFactory keyFactory;

	private static SecretKey key;

	private static final String UNICODE_FORMAT = "UTF-8";

	private static String getKey() {
		return "123CSM34567890ENCRYPTIONC3PR4KEY5678901234567890";
	}
	
	public DESEncryption() {
		super();
	}

	/* (non-Javadoc)
	 * @see gov.nih.nci.security.util.Encryption#encrypt(java.lang.String)
	 */
	@Override
	public synchronized String encrypt(String unencryptedString) throws EncryptionException {
		if (unencryptedString == null || unencryptedString.trim().length() == 0)
			throw new IllegalArgumentException(
					"unencrypted string was null or empty");

		return Base64.getEncoder().encodeToString(unencryptedString.getBytes());
	}

	/* (non-Javadoc)
	 * @see gov.nih.nci.security.util.Encryption#decrypt(java.lang.String)
	 */
	@Override
	public synchronized String decrypt(String encryptedString) throws EncryptionException {
		if (encryptedString == null || encryptedString.trim().length() <= 0)
			throw new IllegalArgumentException(
					"encrypted string was null or empty");

		byte[] decodedBytes = Base64.getDecoder().decode(encryptedString);
		return (new String(decodedBytes)); 
	}
}