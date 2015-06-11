package com.maikalal.autack.ifs.test;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.apache.commons.codec.binary.Hex;

public class TBouncyCastleAPI {

	/**
	 * @param args
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchPaddingException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws InvalidParameterSpecException
	 * @throws IOException
	 */
	public static void main(String[] args) throws NoSuchAlgorithmException,
			InvalidKeySpecException, NoSuchPaddingException,
			InvalidKeyException, InvalidAlgorithmParameterException,
			IllegalBlockSizeException, BadPaddingException,
			InvalidParameterSpecException, IOException {
		// generate key pair

		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.genKeyPair();

		// extract the encoded private key, this is an unencrypted PKCS#8
		// private key
		byte[] encodedprivkey = keyPair.getPrivate().getEncoded();

		// We must use a PasswordBasedEncryption algorithm in order to encrypt
		// the private key, you may use any common algorithm supported by
		// openssl, you can check them in the openssl documentation
		// http://www.openssl.org/docs/apps/pkcs8.html
		final String _MYPBEALG = "PBEWithSHA1AndDESede";
		final String _key_password = "CashFac01";

		int count = 20;// hash iteration count
		Random random = new Random();
		byte[] salt = new byte[8];
		random.nextBytes(salt);

		// Create PBE parameter set
		PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt, count);
		PBEKeySpec pbeKeySpec = new PBEKeySpec(_key_password.toCharArray());
		SecretKeyFactory keyFac = SecretKeyFactory.getInstance(_MYPBEALG);
		SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);

		Cipher pbeCipher = Cipher.getInstance(_MYPBEALG);

		// Initialize PBE Cipher with key and parameters
		pbeCipher.init(Cipher.ENCRYPT_MODE, pbeKey, pbeParamSpec);

		// Encrypt the encoded Private Key with the PBE key
		byte[] ciphertext = pbeCipher.doFinal(encodedprivkey);

		// Now construct PKCS #8 EncryptedPrivateKeyInfo object
		AlgorithmParameters algparms = AlgorithmParameters
				.getInstance(_MYPBEALG);
		algparms.init(pbeParamSpec);
		EncryptedPrivateKeyInfo encinfo = new EncryptedPrivateKeyInfo(algparms,
				ciphertext);

		// and here we have it! a DER encoded PKCS#8 encrypted key!
		byte[] encryptedPkcs8 = encinfo.getEncoded();
		System.out.println("encryptedPkcs8 :\n"
				+ Hex.encodeHexString(encryptedPkcs8));

	}

}
