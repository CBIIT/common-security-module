/*L
 *  Copyright Ekagra Software Technologies Ltd.
 *  Copyright SAIC, SAIC-Frederick
 *
 *  Distributed under the OSI-approved BSD 3-Clause License.
 *  See http://ncip.github.com/common-security-module/LICENSE.txt for details.
 */

package gov.nih.nci.security.util;

import gov.nih.nci.security.exceptions.CSConfigurationException;
import gov.nih.nci.security.util.StringEncrypter.EncryptionException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

import java.util.Base64;
import java.util.Arrays;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class AESEncryption implements Encryption {

    private Cipher encryptCipher;
    private Cipher decryptCipher;
    private Provider provider;
    private static final String AES_ENCRYPTION_SCHEME = "AES";
    private static final String AES_ALGORITHM = "AES";
    private static final String UNICODE_FORMAT = "UTF-8";
    private static final String SALT = "SECRET INGREDIENT";
    private static final String MD5_HASH = "MD5";
    public static final String PASSWORD_HASH_ALGORITHM = "SHA-256";

	private static String secretKey;
    public AESEncryption(String passphrase, boolean isMD5Hash) throws EncryptionException
    {
		String paddedKey = String.format("%-16s", passphrase).replace(' ', '0');
		secretKey = paddedKey;
	}		
    
    @Override
	public String encrypt(String unencryptedString) throws EncryptionException {
		if (unencryptedString == null || unencryptedString.trim().length() == 0)
			throw new IllegalArgumentException(
					"unencrypted string was null or empty");
	try {
		SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(), "AES");
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        // Generate a random IV
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[cipher.getBlockSize()];
        random.nextBytes(iv);

        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(iv));

        byte[] encryptedBytes = cipher.doFinal(unencryptedString.getBytes());
        
        // Combine the IV and encrypted data for transmission/storage
        byte[] combined = new byte[iv.length + encryptedBytes.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encryptedBytes, 0, combined, iv.length, encryptedBytes.length);

        return Base64.getEncoder().encodeToString(combined);  			
		} catch (Exception e) {
			e.printStackTrace();
			throw new EncryptionException(e);
		}
	}

	@Override
	public String decrypt(String encryptedString) throws EncryptionException {	
		if (encryptedString == null || encryptedString.trim().length() <= 0)
			throw new IllegalArgumentException(
					"encrypted string was null or empty");

	try {
		SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        byte[] combined = Base64.getDecoder().decode(encryptedString);
        byte[] iv = new byte[cipher.getBlockSize()];
        System.arraycopy(combined, 0, iv, 0, iv.length);

        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(iv));

        byte[] encryptedBytes = new byte[combined.length - iv.length];
        System.arraycopy(combined, iv.length, encryptedBytes, 0, encryptedBytes.length);

        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes);      			
 		} catch (Exception e) {
			e.printStackTrace();
			throw new EncryptionException(e);
		}            		
	}
}
