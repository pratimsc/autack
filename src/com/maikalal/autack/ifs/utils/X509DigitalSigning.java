package com.maikalal.autack.ifs.utils;

import java.security.*;
import java.security.cert.Certificate;
import java.util.HashMap;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public final class X509DigitalSigning {

	public final static Provider CRYPTO_PROVIDER = new BouncyCastleProvider();

	private final static HashMap<String, String> ALLOWED_MESSAGE_DIGEST_ALGORITHM = new HashMap<String, String>();
	private final static HashMap<String, String> ALLOWED_SIGNATURE_ALGORITHM = new HashMap<String, String>();
	static {

		for (Service service : CRYPTO_PROVIDER.getServices()) {
			if (service.getType().equalsIgnoreCase("MessageDigest")) {
				ALLOWED_MESSAGE_DIGEST_ALGORITHM.put(service.getAlgorithm()
						.trim().toUpperCase(), service.getAlgorithm());
			} else if (service.getType().equalsIgnoreCase("Signature")) {
				ALLOWED_SIGNATURE_ALGORITHM.put(service.getAlgorithm().trim()
						.toUpperCase(), service.getAlgorithm());
			}else{
				continue;
			}
		}
		ALLOWED_MESSAGE_DIGEST_ALGORITHM.remove(null);
		ALLOWED_SIGNATURE_ALGORITHM.remove(null);
	}

	private X509DigitalSigning() {
		// Do not allow creation of any instance, as this is just a utility
		// class;
	}

	public static byte[] createHashSignatureOfData(byte[] data, String algorithm)
			throws NoSuchAlgorithmException {
		if (data == null)
			return null;
		if (algorithm == null) {
			return null;
		}

		MessageDigest md = MessageDigest.getInstance(algorithm.toUpperCase(),
				CRYPTO_PROVIDER);
		md.update(data);		
		byte[] hashedData = md.digest();
		return hashedData;
	}

	public static byte[] createDigitalSignatureOfData(byte[] data,
			String signatureAlgorithm, PrivateKey privateKey)
			throws NoSuchAlgorithmException, InvalidKeyException,
			SignatureException, NoSuchProviderException {
		if (data == null || data.length == 0) {
			return null;
		}
		if (signatureAlgorithm == null || signatureAlgorithm.isEmpty()) {
			return null;
		}

		Signature signature = Signature.getInstance(signatureAlgorithm,
				CRYPTO_PROVIDER);
		System.out.println("Crypto Provider :" + signature.getProvider());
		signature.initSign(privateKey);
		signature.update(data);
		return signature.sign();
	}

	public static boolean verifyDigitalSignatureOfData(byte[] signedData,
			byte[] signatureData, String signatureAlgorithm, PublicKey publicKey)
			throws NoSuchAlgorithmException, InvalidKeyException,
			SignatureException {
		if (signedData == null || signedData.length == 0) {
			return false;
		}
		if (signatureAlgorithm == null || signatureAlgorithm.isEmpty()) {
			signatureAlgorithm = publicKey.getAlgorithm();
		}

		//Signature signatureVerifier = Signature.getInstance(signatureAlgorithm,CRYPTO_PROVIDER);
		Signature signatureVerifier = Signature.getInstance(signatureAlgorithm);
		signatureVerifier.initVerify(publicKey);
		signatureVerifier.update(signedData);
		return signatureVerifier.verify(signatureData);
	}

	public static boolean verifyDigitalSignatureOfData(byte[] signedData,
			byte[] signatureData, PublicKey publicKey)
			throws NoSuchAlgorithmException, InvalidKeyException,
			SignatureException {
		return verifyDigitalSignatureOfData(signedData, signatureData, null,
				publicKey);
	}

	public static PrivateKey fetchPrivateKeyFromKeyStore(KeyStore keyStore,
			String privateKeyAlias, String privateKeyPassword)
			throws UnrecoverableKeyException, KeyStoreException,
			NoSuchAlgorithmException {
		if (keyStore == null || privateKeyAlias == null
				|| privateKeyAlias.isEmpty() || privateKeyPassword == null) {
			return null;
		}
		Key privateKey = keyStore.getKey(privateKeyAlias,
				privateKeyPassword.toCharArray());
		if (privateKey != null) {
			return (PrivateKey) privateKey;
		}
		return null;
	}

	public static PublicKey fetchPublicKeyFromKeyStore(KeyStore keyStore,
			String publicKeyAlias) throws KeyStoreException {
		if (keyStore == null || publicKeyAlias == null
				|| publicKeyAlias.isEmpty()) {
			return null;
		}
		Certificate publicCertificate = keyStore.getCertificate(publicKeyAlias);
		PublicKey publicKey = publicCertificate.getPublicKey();
		if (publicKey != null) {
			return publicKey;
		}
		return null;
	}

	public static Provider getCryptoProvider() {
		return CRYPTO_PROVIDER;
	}

	public static HashMap<String, String> getAllowedMessageDigestAlgorithm() {
		return ALLOWED_MESSAGE_DIGEST_ALGORITHM;
	}

	public static HashMap<String, String> getAllowedSignatureAlgorithm() {
		return ALLOWED_SIGNATURE_ALGORITHM;
	}

}
