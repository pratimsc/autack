package com.maikalal.autack.ifs.test;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.identrus.isil.Signature;
import com.maikalal.autack.ifs.utils.EDIFACTMessageProcessor;
import com.maikalal.autack.ifs.utils.X509DigitalSigning;

public class TDigitalSigning {

	public static void main(String[] args) throws KeyStoreException,
			IOException, NoSuchAlgorithmException, CertificateException,
			UnrecoverableKeyException, InvalidKeyException, SignatureException,
			DecoderException, NoSuchProviderException {
		Security.addProvider(new BouncyCastleProvider());
		
		// File file = new File(System.getProperty("user.home") +
		// File.separatorChar + ".keystore");
		// File file = new File("B:/Official/PKI/X509_PoC/work/AMSTest/ifs");
		File file = new File(
				"B:/Official/PKI/X509_PoC/work/AMSTest/ifs.messageway.test");

		System.out.println("File:" + file.getCanonicalPath()+", KeyStore.getDefaultType():"+KeyStore.getDefaultType());
		FileInputStream fin = new FileInputStream(file);
		
		//KeyStore keyStore = KeyStore.getInstance("JKS");
		//keyStore.load(fin, "Password1234@".toCharArray());
		
		/*
		 * Start Signing code using Gemalto 
		 */
		String digestAlgorithm = "SHA1";
		String encryptionAlgorithm = "RSA";
		String algorithm = "SHA1withRSA";
		System.out.println("going to sign with algorithm: " + algorithm);  // prints "SHA1withRSA" 
				
		String providerName = null;
		KeyStore keyStore = KeyStore.getInstance("PKCS11");
		keyStore.load(null, "87654321".toCharArray());
		Signature sig = new Signature();
		sig.setIsDebug(true);
		System.out.println("sig.getSupportedVersions()->"+sig.getSupportedVersions());
		
		/*
		 * --END
		 */

		/*
		 * Enumeration<String> aliases = keyStore.aliases(); if (aliases !=
		 * null) { while (aliases.hasMoreElements()) { String key = (String)
		 * aliases.nextElement(); System.out.println(
		 * "_________________________________________________________");
		 * System.out.println("Key ->"+key); System.out.println("Value->");
		 * System.out.println(keyStore.getCertificate(key)); System.out.println(
		 * "_________________________________________________________"); } }
		 * System.out
		 * .println("#############################################################"
		 * );
		 */

		/*
		 * Start the test of Digital signing.
		 */
		// String myMessage = "This is my sample test message.";
		// String myMessage =
		// "UNH+1+PAYEXT:2:912:UN'BGM+451+072315123911+137:20120723:102+9'NAD+OY+BARCA:160:ZZZ++BAR COUNCIL SERVICES+289-293 HIGH HOLBORN+HIGH HOLBORN+.+WC1V 7HZ+GB'NAD+BE+BARCA:160:ZZZ++BAR COUNCIL SERVICES+289-293 HIGH HOLBORN+HIGH HOLBORN+.+WC1V 7HZ+GB'FII+OR+90216291:BAR COUNCIL SERVICES+:::207929:154:133'FII+BF+80888737:BAR COUNCIL SERVICES+:::207929:154:133'DTM+209:20120723:102'MOA+7+9:0.10:GBP'FTX+PMD+++07231512391'UNS+S'MOA+3+128:0.10:GBP'UNT+12+1'UNH+2+PAYEXT:2:912:UN'BGM+451+072305485212+137:20120723:102+9'NAD+OY+BARCA:160:ZZZ++BAR COUNCIL SERVICES+289-293 HIGH HOLBORN+HIGH HOLBORN+.+WC1V 7HZ+GB'NAD+BE+7230548521:160:ZZZ++BCG NO NFS TEST+.+.+.+.+GB'FII+OR+80888737:BAR COUNCIL SERVICES+:::207929:154:133'FII+BF+90216291:BCG NO NFS TEST+:::207929:154:133'DTM+209:20120723:102'PAI+:::B01'MOA+7+9:0.10:GBP'FTX+PMD+++BCG NO NFS TEST'UNS+S'MOA+3+128:0.10:GBP'UNT+13+2'";
		// String myMessage = getContentOfFile(new
		// File("B:/Official/PKI/X509_PoC/work/AMSTest/PAEXTPayment.File.txt")).toString();
		String myMessage = getContentOfFile(
				new File(
						"B:/Official/PKI/X509_PoC/work/AMSTest/PAEXTPayment.File.20120914_1.txt"))
				.toString();
		System.out.println("Original message ->" + myMessage);
		System.out.println("BYTE[] of original message ->"
				+ myMessage.getBytes(Charset.forName("UTF-8")));

		// Get the HASHED value of the data
		byte[] myMessageHashedByte = X509DigitalSigning
				.createHashSignatureOfData(
						myMessage.getBytes(Charset.forName("UTF-8")),
						"SHA1");
		System.out.println("The digitally Hashed message byte[]is ------->"
				+ myMessageHashedByte);
		System.out.println("The digitally Hashed message HEX format is -->");
		System.out.println(Hex.encodeHexString(myMessageHashedByte));

		// Digitally sign the HEX representation of Hashed data
		// PrivateKey privateKey =
		// X509DigitalSigning.fetchPrivateKeyFromKeyStore(keyStore,
		// "pratim_ifs", "G0d1sEverywh9r9@");
		// PrivateKey privateKey =
		// X509DigitalSigning.fetchPrivateKeyFromKeyStore(keyStore,
		// "pratim_ifs_1024", "Password1234@");
		PrivateKey privateKey = X509DigitalSigning.fetchPrivateKeyFromKeyStore(
				keyStore, "ifs_messageway_2048_SHA1", "Password1234@");
		byte[] signedMessageByte = X509DigitalSigning
				.createDigitalSignatureOfData(
						Hex.encodeHexString(myMessageHashedByte).getBytes(),
						"SHA1withRSA",
						privateKey);

		System.out
				.println("The digitally X.509 signed message is in byte[]--->"
						+ signedMessageByte);
		System.out
				.println("The digitally X.509 signed message is HEX format-->");
		String signedMessageHexString = Hex.encodeHexString(signedMessageByte);
		System.out.println(signedMessageHexString);

		// Validate the Digital signature
		// PublicKey publicKey =
		// X509DigitalSigning.fetchPublicKeyFromKeyStore(keyStore,
		// "pratim_ifs");
		// PublicKey publicKey =
		// X509DigitalSigning.fetchPublicKeyFromKeyStore(keyStore,
		// "pratim_ifs_1024");
		PublicKey publicKey = X509DigitalSigning.fetchPublicKeyFromKeyStore(keyStore, "ifs_messageway_2048_SHA1");
		//PublicKey publicKey = X509DigitalSigning.fetchPublicKeyFromKeyStore(keyStore, "ifs_messageway_1024_sha1");
		System.out.println("publicKey.getAlgorithm() ->"+publicKey.getAlgorithm());
		
		RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
		System.out.println("rsaPublicKey.getModulus()               :"+rsaPublicKey.getModulus());
		System.out.println("rsaPublicKey.getModulus() in HEX        :"+rsaPublicKey.getModulus().toString(16));
		System.out.println("rsaPublicKey.getPublicExponent()        :"+rsaPublicKey.getPublicExponent());
		System.out.println("rsaPublicKey.getPublicExponent() in HEX :"+rsaPublicKey.getPublicExponent().toString(16));
		
		//System.out.println("RSAPublicKey Hex.encodeHexString -> "+Hex.encodeHexString(rsaPublicKey.getEncoded()));
		String str1 = "f9e95ee98d73b77e9d17498accea4c40d860d5dc";
		//String str2 = "392ca492985eafb392a040661eb7f1a21f5836f568161c1b36205a4cdcc49c5f5fb94076c439cef8cfb03aadd1bcc00f18f0507e65bb6b1645113df516f61c9b876eab1f3211f561e0550ce7f537adf8295f505538c90975798ed0ff4517f01582de8b33c5eca8d2827fd9cae964cad90b342c8da888db626d39982457d09b42a6d06262389fc9d03fc3747b0f30c022460355b989cf754be5b24df872b2dcc40572da1707afac16cbc6bd1ca3fac71c7b0fa30ecbaf52840e731fe181ad4311c462d5cf383be446cb0f350705afe0270ebdd10a71cb5c379b8851b3471831ea87aab16d646a1c6c97c549ddb3db23d2dc69adc0266a0bd072d10d76e7ea2177";
		String str2 = "657a51196e7160a5aa17dfb8c4e5db588d3f0702c1f1690a88854642121aab717e37691221dcebfbd04820c03db12128379848408bfe5f2102c867349adb9c3b2335f377182c3e0d5d2341ed1dff38b271027ab2ea48f16b70dc1fad118dad20cd1a27633125e4ff18c4b89b1e343519ba466cbc007f50321bd16c10ac85d34e0ab5aebbe88fc4cc3cb645690223b6cd1d4176fbc79f9d2dc7c161a53af34d51cef6b0ddfb952f46ff97aa0b946f887f110e82a0f1193d59f004e3cae99fb6730139582b7f13e1dc7e7c5bbd6b11e576e0f64e7e61bb905fe0eccf7a67bd6f81884f79ea527f7960d30b1d33398b336491774e26965a7792701cacc3714d539b";
		System.out.println("######Bytes ->"+Hex.decodeHex(str2.toCharArray()));
		/*
		 * #################################################################################
		 */
		System.out
		.println("######Is the signature valid?"
				+ X509DigitalSigning
						.verifyDigitalSignatureOfData(
								Hex.decodeHex(str1.toCharArray()),
								Hex.decodeHex(str2.toCharArray()),
								"RSA",
								rsaPublicKey));
		System.out
		.println("######Is the signature valid?"
				+ X509DigitalSigning
						.verifyDigitalSignatureOfData(
								Hex.decodeHex(str1.toCharArray()),
								Hex.decodeHex(str2.toCharArray()),
								"SHA1withRSAEncryption",
								rsaPublicKey));
		System.out
		.println("######Is the signature valid?"
				+ X509DigitalSigning
						.verifyDigitalSignatureOfData(
								Hex.decodeHex(str1.toCharArray()),
								Hex.decodeHex(str2.toCharArray()),
								"MD5withRSAEncryption",
								rsaPublicKey));
		/*
		 * #################################################################################
		 */
		System.out
				.println("Is the signature valid?"
						+ X509DigitalSigning
								.verifyDigitalSignatureOfData(
										Hex.encodeHexString(myMessageHashedByte)
												.getBytes(),
										signedMessageByte,
										"SHA1withRSA",
										rsaPublicKey));

		// Generate an AUTACK Message
		// String certificateReferenceInMessageWay="XYZ001";
		// String interchangeSenderCustomerName="GRESHAM";
		// String interchangeControlReference="1220555473";
		String certificateReferenceInMessageWay = "XYZ001";
		String interchangeSenderCustomerName = "GRESHAM";
		String interchangeControlReference = "2330555478";

		String autackMessage = EDIFACTMessageProcessor
				.generateAUTACKMessageBlockForBarclays(myMessage, privateKey,
						"SHA1",
						"SHA1withRSA",
						certificateReferenceInMessageWay,
						interchangeSenderCustomerName,
						interchangeControlReference, true);
		//System.out.println("EDIFACT AUTACK BLOCK -----");
		//System.out.println(autackMessage);
	}

	public static StringBuilder getContentOfFile(File inputFile)
			throws IOException {

		BufferedReader br = new BufferedReader(new FileReader(inputFile));
		StringBuilder sb = new StringBuilder();

		while (true) {
			String line = br.readLine();

			if (line == null) {
				break;
			} else {
				sb.append(line);
			}
		}
		return sb;
	}
}
