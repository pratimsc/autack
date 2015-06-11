package com.maikalal.autack.ifs.test;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.maikalal.autack.ifs.utils.X509DigitalSigning;

public class TCheckGreshamPaymentFile {

	public static void main(String[] args) throws IOException,
			KeyStoreException, NoSuchAlgorithmException, CertificateException,
			DecoderException, InvalidKeyException, SignatureException {
		Security.addProvider(new BouncyCastleProvider());

		// File file = new File(System.getProperty("user.home") +
		// File.separatorChar + ".keystore");
		// File file = new File("B:/Official/PKI/X509_PoC/work/AMSTest/ifs");
		File file = new File(
				"B:/Official/PKI/X509_PoC/work/AMSTest/ifs.messageway.test");

		System.out.println("File:" + file.getCanonicalPath()
				+ ", KeyStore.getDefaultType():" + KeyStore.getDefaultType());
		FileInputStream fin = new FileInputStream(file);

		KeyStore keyStore = KeyStore.getInstance("JKS");
		keyStore.load(fin, "Password1234@".toCharArray());

		/*
		 * Start the test of Digital signing.
		 */
		String myMessage = "UNH+1+PAYEXT:2:912:UN'"
				+ "BGM+451+112004302011+137:20121120:102+9'"
				+ "NAD+OY+GBP:160:ZZZ++GBP CURRENCY+.+.+.+.+GB'"
				+ "NAD+BE+11200430201:160:ZZZ++PAYEE+.+.+.+.+GB'"
				+ "FII+OR+11111111:GBP CURRENCY+:::202020:154:133'"
				+ "FII+BF+12345678:PAYEE+:::204657:154:133'"
				+ "DTM+209:20121120:102'" + "PAI+:::B01'"
				+ "MOA+7+9:111.00:GBP'" + "FTX+PMD+++REF'" + "UNS+S'"
				+ "MOA+3+128:111.00:GBP'" + "UNT+13+1'";

		System.out.println("Original message ->\n" + myMessage);
		System.out.println("BYTE[] of original message ->\n"
				+ myMessage.getBytes(Charset.forName("UTF-8")));

		// Get the HASHED value of the data
		byte[] myOriginalMessageHashedByte = X509DigitalSigning
				.createHashSignatureOfData(
						myMessage.getBytes(Charset.forName("UTF-8")), "SHA1");
		System.out.println("The digitally Hashed message byte[]is ------->"
				+ myOriginalMessageHashedByte);
		System.out.println("The digitally Hashed message HEX format is -->"
				+ Hex.encodeHexString(myOriginalMessageHashedByte));

		String signedMessageInHex = "9AEC3755224EF7EBCBC61D0FE6336018F94846326FE4CDE348B67DC3D26D70770EEA86F73A5EC1BEA6D2C1D39A6A19DC66194CFF405C375B2D2B7EA56DA7211952F8899F189B6D8E3DDAE83D2077B761C6EBEBC25EA7A7151D3AF7FCF18E00C2A8F43487CDB317D1854FC17228538CF2BB39C9F3B979AC8CED51A2DB0F93D197"
				.toLowerCase();
		//signedMessageInHex = "b3ee5b4be32f6321601dfcecbca3f276176bbfbca5f2e901103bf2ed1f41a07d5d2fa6364f686015d6fc1b88cee5602e6b1b7d747d3371b1fc08a7e8150a5f6c78d5744931ea8266189a2d5be23983b74154d8998fe766635edf8fd814a735fca792acaca9f99fe27ca3c31ba3984cb97a0854fa7e3bb0a97933265990c2b5a3";
		// String signedMessageInHex =
		// "937c089a23939c834c1fb2050dfaa0ded156d1f466f60dd13e77c6ef6dc6721cb693f7d03475df08f2b382c23acb1689d0ac7c9ff06fa32b423f5b6bdb4d11b20d4a90c2982496f5a21988ab28adbc7245a97abcae25c81f2a83771462c68aebbf7f5f19c661a52029279bb118f1f96b3a92e67c3f6651a2185ed854c6219f4b267a1e22d0086203c6ac0cb7a59343be7b854164852f5670c4e79081e1b11e62fbc507bc2ebe486c33dd9a95257c8a9647c653d01aa9832680ebf4890b4647ec2ba5f95ee2c5407389b708e3f12967c58994cec556f58c01ad0b74d525cd101bcf26da19845309b2560a30979182a71e5466771b642c25700dafe84be94216f9";
		byte[] signedMessageByte = Hex.decodeHex(signedMessageInHex
				.toCharArray());
		System.out
				.println("The digitally X.509 signed message is in byte[] SIZE --->\n"
						+ signedMessageByte.length);
		System.out
				.println("The digitally X.509 signed message is in byte[]--->\n"
						+ signedMessageByte);
		System.out
				.println("The digitally X.509 signed message is HEX format-->\n"
						+ signedMessageInHex);
		System.out.println();

		System.out
				.println("######################################################################");
		// Validate the Digital signature
		PublicKey publicKeyUtility = X509DigitalSigning.fetchPublicKeyFromKeyStore(keyStore, "david_trigwell_utility");
		//PublicKey publicKeyUtility =X509DigitalSigning.fetchPublicKeyFromKeyStore(keyStore,"test_rsa_1024_1");
		RSAPublicKey rsaPublicKeyUtility = (RSAPublicKey) publicKeyUtility;
		System.out.println("rsaPublicKeyUtility.getAlgorithm()             :\n"
				+ rsaPublicKeyUtility.getAlgorithm());
		System.out.println("rsaPublicKeyUtility.getModulus()               :\n"
				+ rsaPublicKeyUtility.getModulus());
		System.out.println("rsaPublicKeyUtility.getModulus() in HEX        :\n"
				+ rsaPublicKeyUtility.getModulus().toString(16));
		System.out.println("rsaPublicKeyUtility.getPublicExponent()        :\n"
				+ rsaPublicKeyUtility.getPublicExponent());
		System.out.println("rsaPublicKeyUtility.getPublicExponent() in HEX :\n"
				+ rsaPublicKeyUtility.getPublicExponent().toString(16));

		decryptDataUsingPublicKey(publicKeyUtility, signedMessageByte);
		/*
		 * ######################################################################
		 * ###########
		 */
		/*System.out.println("######Is the signature valid?"
				+ rsaPublicKeyUtility.getAlgorithm()
				+ X509DigitalSigning
						.verifyDigitalSignatureOfData(
								myOriginalMessageHashedByte, signedMessageByte,
								rsaPublicKeyUtility.getAlgorithm(),
								rsaPublicKeyUtility));
		System.out
				.println("######Is the signature valid SHA1withRSAEncryption?"
						+ X509DigitalSigning.verifyDigitalSignatureOfData(
								myOriginalMessageHashedByte, signedMessageByte,
								"SHA1withRSAEncryption", rsaPublicKeyUtility));
		System.out.println("######Is the signature valid MD5withRSAEncryption?"
				+ X509DigitalSigning.verifyDigitalSignatureOfData(
						myOriginalMessageHashedByte, signedMessageByte,
						"MD5withRSAEncryption", rsaPublicKeyUtility));
		System.out.println("######Is the signature valid SHA1withRSA?"
				+ X509DigitalSigning.verifyDigitalSignatureOfData(
						myOriginalMessageHashedByte, signedMessageByte,
						"SHA1withRSA", rsaPublicKeyUtility));

		System.out.println("######Is the signature valid SHA1withRSA/PSS?"
				+ X509DigitalSigning.verifyDigitalSignatureOfData(
						myOriginalMessageHashedByte, signedMessageByte,
						"SHA1withRSA/PSS", rsaPublicKeyUtility));

		System.out
				.println("######Is the signature valid SHA1withRSA/ISO9796-2?"
						+ X509DigitalSigning.verifyDigitalSignatureOfData(
								myOriginalMessageHashedByte, signedMessageByte,
								"SHA1withRSA/ISO9796-2", rsaPublicKeyUtility));
		System.out.println("######Is the signature valid SHA1WITHECNR?"
				+ X509DigitalSigning.verifyDigitalSignatureOfData(
						myOriginalMessageHashedByte, signedMessageByte,
						"SHA1WITHECNR", rsaPublicKeyUtility));
		System.out.println("######Is the signature valid RSA?"
				+ X509DigitalSigning.verifyDigitalSignatureOfData(
						myOriginalMessageHashedByte, signedMessageByte, "RSA",
						rsaPublicKeyUtility));
		System.out.println("######Is the signature valid SHA1WITHCVC-ECDSA?"
				+ X509DigitalSigning.verifyDigitalSignatureOfData(
						myOriginalMessageHashedByte, signedMessageByte,
						"SHA1WITHCVC-ECDSA", rsaPublicKeyUtility));*/

		System.out
				.println("######################################################################");
		PublicKey publicKeyIdentity = X509DigitalSigning
				.fetchPublicKeyFromKeyStore(keyStore, "david_trigwell_identity");
		RSAPublicKey rsaPublicKeyIdentity = (RSAPublicKey) publicKeyIdentity;
		System.out
				.println("rsaPublicKeyIdentity.getAlgorithm()             :\n"
						+ rsaPublicKeyIdentity.getAlgorithm());
		System.out
				.println("rsaPublicKeyIdentity.getModulus()               :\n"
						+ rsaPublicKeyIdentity.getModulus());
		System.out
				.println("rsaPublicKeyIdentity.getModulus() in HEX        :\n"
						+ rsaPublicKeyIdentity.getModulus().toString(16));
		System.out
				.println("rsaPublicKeyIdentity.getPublicExponent()        :\n"
						+ rsaPublicKeyIdentity.getPublicExponent());
		System.out
				.println("rsaPublicKeyIdentity.getPublicExponent() in HEX :\n"
						+ rsaPublicKeyIdentity.getPublicExponent().toString(16));
		decryptDataUsingPublicKey(publicKeyIdentity, signedMessageByte);
		/*
		 * ######################################################################
		 * ###########
		 */
		/*System.out.println("######Is the signature valid?"
				+ X509DigitalSigning.verifyDigitalSignatureOfData(
						myOriginalMessageHashedByte, signedMessageByte,
						rsaPublicKeyIdentity.getAlgorithm(),
						rsaPublicKeyIdentity));
		System.out.println("######Is the signature valid?"
				+ X509DigitalSigning.verifyDigitalSignatureOfData(
						myOriginalMessageHashedByte, signedMessageByte,
						"SHA1withRSAEncryption", rsaPublicKeyIdentity));
		System.out.println("######Is the signature valid?"
				+ X509DigitalSigning.verifyDigitalSignatureOfData(
						myOriginalMessageHashedByte, signedMessageByte,
						"MD5withRSAEncryption", rsaPublicKeyIdentity));
		System.out.println("######Is the signature valid?"
				+ X509DigitalSigning.verifyDigitalSignatureOfData(
						myOriginalMessageHashedByte, signedMessageByte,
						"SHA1withRSA", rsaPublicKeyIdentity));

		System.out.println("######Is the signature valid?"
				+ X509DigitalSigning.verifyDigitalSignatureOfData(
						myOriginalMessageHashedByte, signedMessageByte,
						"SHA1withRSA/PSS", rsaPublicKeyIdentity));

		System.out.println("######Is the signature valid?"
				+ X509DigitalSigning.verifyDigitalSignatureOfData(
						myOriginalMessageHashedByte, signedMessageByte,
						"SHA1withRSA/ISO9796-2", rsaPublicKeyIdentity));
		System.out.println("######Is the signature valid?"
				+ X509DigitalSigning.verifyDigitalSignatureOfData(
						myOriginalMessageHashedByte, signedMessageByte,
						"SHA1WITHECNR", rsaPublicKeyIdentity));
		System.out.println("######Is the signature valid?"
				+ X509DigitalSigning.verifyDigitalSignatureOfData(
						myOriginalMessageHashedByte, signedMessageByte, "RSA",
						rsaPublicKeyIdentity));
		System.out.println("######Is the signature valid?"
				+ X509DigitalSigning.verifyDigitalSignatureOfData(
						myOriginalMessageHashedByte, signedMessageByte,
						"SHA1WITHCVC-ECDSA", rsaPublicKeyIdentity));*/
	}
	
	public static void decryptDataUsingPublicKey(PublicKey publicKey, byte[] cipherText){
		try {
			Cipher cipher = Cipher.getInstance("RSA", "BC");
			cipher.init(Cipher.DECRYPT_MODE, publicKey);
			byte[] plainText = cipher.doFinal(cipherText);
			System.out.println("Decrypted the message using "+publicKey.toString()+"->"+Hex.encodeHexString(plainText));
			
		} catch (NoSuchAlgorithmException | NoSuchProviderException
				| NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}
		
	}

}
