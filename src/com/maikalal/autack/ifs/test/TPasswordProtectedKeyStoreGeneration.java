package com.maikalal.autack.ifs.test;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.Enumeration;

public class TPasswordProtectedKeyStoreGeneration {

	public static void main(String[] args) throws IOException,
			KeyStoreException, NoSuchProviderException,
			NoSuchAlgorithmException, CertificateException,
			UnrecoverableKeyException {

		File file = new File("c:/data/tmp/bctest/aJKS.keystore");
		System.out.println("Source File:" + file.getCanonicalPath()
				+ ", KeyStore.getDefaultType():" + KeyStore.getDefaultType());
		FileInputStream fin = new FileInputStream(file);
		KeyStore srcKeyStore = KeyStore.getInstance("JKS", "SUN");
		srcKeyStore.load(fin, "Password1234@".toCharArray());

		/*
		 * Bouncy castle specific operations
		 */
		String bcKeyStorePassword = "ADumbKeyStorePassword";
		String bcPrivateKeyPassword = "AReallyDumbPrivateKeyPassword";
		// KeyStore bcKeyStore = KeyStore.getInstance("UBER", "BC");
		KeyStore bcKeyStore = KeyStore.getInstance("JKS", "SUN");
		System.out.println("Got an instance of KeyStore.");
		bcKeyStore.load(null, bcKeyStorePassword.toCharArray());
		System.out.println("Set the password of the keystore");

		/*
		 * Transfer Keys from JKS to BC
		 */
		String jkPrivateKeyAlias = "ifs_messageway_2048_SHA1";
		String jkPivateKeyPassword = "Password1234@";
		RSAPrivateCrtKey jkPrivateKey = (RSAPrivateCrtKey) srcKeyStore.getKey(
				jkPrivateKeyAlias, jkPivateKeyPassword.toCharArray());
		System.out.println("Extracted Private key '" + jkPrivateKeyAlias
				+ "'from SUN JKS");
		Certificate[] jkPublicCertificate = srcKeyStore
				.getCertificateChain(jkPrivateKeyAlias);
		System.out
				.println("Extracted Certificate chain associated with Private key '"
						+ jkPrivateKeyAlias + "'");
		PublicKey jkPublicKey = jkPublicCertificate[0].getPublicKey();
		System.out.println("Extracted Public key '" + jkPrivateKeyAlias
				+ "'from " + srcKeyStore.getType());
		bcKeyStore.setKeyEntry(jkPrivateKeyAlias, jkPrivateKey,
				jkPivateKeyPassword.toCharArray(), jkPublicCertificate);
		System.out.println("Stored Private key '" + jkPrivateKeyAlias + "' in "
				+ bcKeyStore.getType() + " Keystore");
		/*
		 * Write the UBER key store in file system
		 */
		File bcKSFile = new File("c:/data/tmp/bctest/anUber.keystore");
		FileOutputStream bcFout = new FileOutputStream(bcKSFile);
		System.out.println("The new keystore file is "
				+ bcKSFile.getCanonicalPath());
		bcKeyStore.store(bcFout, bcKeyStorePassword.toCharArray());
		bcFout.flush();
		bcFout.close();

		System.out
				.println("Try to list the keys/certificates in the keystore....");
		try {
			Enumeration<String> aliases = bcKeyStore.aliases();
			while (aliases.hasMoreElements()) {
				String name = (String) aliases.nextElement();
				if (bcKeyStore.isKeyEntry(name)) {
					System.out.println("Found key : " + name);
				} else {
					System.out.println("Found certificate : " + name);
				}
			}
		} catch (Exception e) {
			System.out
					.println("Unable to list the contents of the keystore...");
			e.printStackTrace();
		}

	}

}
