package com.maikalal.autack.ifs.cmd;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.*;

import org.apache.commons.cli.*;
import org.apache.commons.codec.DecoderException;

import com.maikalal.autack.ifs.utils.*;

public class DigitalSigningCmd {

	private static final Option help = new Option("help", "print this message");
	private static final Option verbose = new Option("verbose",
			"be extra verbose");

	private static final Option oKeyStore = OptionBuilder
			.withArgName("keystore file")
			.hasArg()
			.withDescription(
					"use the Java keystore file that contains the Private key for digitally signing")
			.create("keyStore");
	private static final Option oKeyStorePwd = OptionBuilder
			.withArgName("keystore password").hasArg()
			.withDescription("password to access the keystore")
			.create("keyStorePassword");
	private static final Option oPaymentFile = OptionBuilder
			.withArgName("PAYEXT payment file")
			.hasArg()
			.withDescription(
					"full path to PAYEXT payment file that has to be digitally signed")
			.create("paymentFile");
	private static final Option oKeyAlias = OptionBuilder
			.withArgName("Private Key Alias").hasArg()
			.withDescription("Alias of the key, as stored in the KeyStore")
			.create("keyAlias");
	private static final Option oKeyPassword = OptionBuilder
			.withArgName("Private Key Password ").hasArg()
			.withDescription("Password for accessing the key")
			.create("keyPassword");
	private static final Option oHashingAlgorithm = OptionBuilder
			.withArgName("Hashing Algorithm").hasArg()
			.withDescription("Hashing algorithm to use.")
			.create("hashAlgorithm");
	private static final Option oSignatureAlgorithm = OptionBuilder
			.withArgName("Signing Algorithm").hasArg()
			.withDescription("Signing algorithm to use.")
			.create("signingAlgorithm");
	private static final Option oMessageWayCertificateReference = OptionBuilder
			.withArgName("MessageWay Public Key Ref Id")
			.hasArg()
			.withDescription(
					"The Public key reference id as stored in MessageWay")
			.create("messageWayKeyId");

	private static final Option oCustomerName = OptionBuilder
			.withArgName("Customer Id")
			.hasArg()
			.withDescription(
					"Optional. Sender customer name as registred in MessageWay. Default is \"DUMMYCUSTOMER\"")
			.create("customerName");

	private static final Option oControlReference = OptionBuilder
			.withArgName("Interchange Control Reference")
			.hasArg()
			.withDescription(
					"Optional. Unique payment file reference number present in file header block. Default is \"REF1234567890\"")
			.create("controlReference");

	private static final Options options = new Options().addOption(help)
			.addOption(verbose).addOption(oKeyStore).addOption(oKeyStorePwd)
			.addOption(oPaymentFile).addOption(oKeyAlias)
			.addOption(oKeyPassword).addOption(oHashingAlgorithm)
			.addOption(oSignatureAlgorithm)
			.addOption(oMessageWayCertificateReference)
			.addOption(oCustomerName).addOption(oControlReference);

	public static void main(String[] args) throws KeyStoreException,
			IOException, NoSuchAlgorithmException, CertificateException,
			UnrecoverableKeyException, InvalidKeyException, SignatureException,
			DecoderException, NoSuchProviderException {
		/**
		 * Use Apache Common CLI to parse the input arguments
		 */
		if (args == null || args.length == 0 || args.length < 8) {
			printHelperMessage();
			System.exit(-1);
		}

		CommandLineParser cliParser = new GnuParser();
		CommandLine line = null;
		try {
			line = cliParser.parse(options, args);
		} catch (org.apache.commons.cli.ParseException e) {
			System.err.println("Parsing failed. Reason:" + e.getMessage());
		}
		if (line == null) {
			printHelperMessage();
			System.exit(-1);
		}
		if (line.hasOption(help.getOpt())) {
			printHelperMessage();
			System.exit(0);
		}

		if (!line.hasOption(oKeyStore.getOpt())
				|| !line.hasOption(oKeyStorePwd.getOpt())
				|| !line.hasOption(oPaymentFile.getOpt())
				|| !line.hasOption(oKeyAlias.getOpt())
				|| !line.hasOption(oKeyPassword.getOpt())
				|| !line.hasOption(oHashingAlgorithm.getOpt())
				|| !line.hasOption(oSignatureAlgorithm.getOpt())
				|| !line.hasOption(oMessageWayCertificateReference.getOpt())) {
			printHelperMessage();
			System.exit(-2);
		}

		File keyStoreFile = new File(line.getOptionValue(oKeyStore.getOpt()));
		String keyStorePassword = line.getOptionValue(oKeyStorePwd.getOpt());
		File paymentFile = new File(line.getOptionValue(oPaymentFile.getOpt()));
		String keyAlias = line.getOptionValue(oKeyAlias.getOpt());
		String keyPassword = line.getOptionValue(oKeyPassword.getOpt());
		String hashAlgorithm = line.getOptionValue(oHashingAlgorithm.getOpt());
		String signingAlgorithm = line.getOptionValue(oSignatureAlgorithm
				.getOpt());
		String messageWayKeyId = line
				.getOptionValue(oMessageWayCertificateReference.getOpt());

		/**
		 * Pre-analyse the supplied algorithms with supported algorithm.
		 */
		hashAlgorithm = X509DigitalSigning.getAllowedMessageDigestAlgorithm()
				.get(hashAlgorithm.toUpperCase());
		if (hashAlgorithm == null || hashAlgorithm.isEmpty()) {
			System.err.print("Provided hashing algorithm not supported.");
			printHelperMessage();
			System.exit(-3);
		}

		signingAlgorithm = X509DigitalSigning.getAllowedSignatureAlgorithm()
				.get(signingAlgorithm.toUpperCase());
		if (signingAlgorithm == null || signingAlgorithm.isEmpty()) {
			System.err.print("Provided signature algorithm not supported.");
			printHelperMessage();
			System.exit(-3);
		}

		/**
		 * Start the Cryptography operation
		 */

		/*
		 * Get the data to be signed
		 */
		System.out
				.println("PaymentFile File:" + paymentFile.getCanonicalPath());
		StringBuilder edifactPaymentFileData = getContentOfFile(paymentFile);
		String myMessage = getContentToBeSigned(edifactPaymentFileData)
				.toString();
		System.out.println("----BEGIN--EDIFACT DATA BLOCK Being signed -----");
		System.out.println(myMessage);
		System.out.println("----BND----EDIFACT DATA BLOCK Being signed -----");
		/*
		 * Fetch the PrivateKey
		 */
		System.out.println("KeyStore File:" + keyStoreFile.getCanonicalPath());
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		keyStore.load(new FileInputStream(keyStoreFile),
				keyStorePassword.toCharArray());
		PrivateKey privateKey = X509DigitalSigning.fetchPrivateKeyFromKeyStore(
				keyStore, keyAlias, keyPassword);

		/**
		 * Carry out operation for AUTACK
		 */
		// Extract customer name
		String customerName = line.getOptionValue(oCustomerName.getOpt());
		if (customerName == null || customerName.isEmpty()) {
			customerName = getCustomerName(edifactPaymentFileData);
			if (customerName == null || customerName.isEmpty()) {
				customerName = "DUMMYCUSTOMER";
			}
		}
		// Extract the interchangeControlReference from File if present.
		String interchangeControlReference = line
				.getOptionValue(oControlReference.getOpt());
		if (interchangeControlReference == null
				|| interchangeControlReference.isEmpty()) {
			interchangeControlReference = getInterchangeControlReference(edifactPaymentFileData);
			if (interchangeControlReference == null
					|| interchangeControlReference.isEmpty()) {
				interchangeControlReference = "REF1234567890";
			}
		}
		// Generate an AUTACK Message
		System.out.println("Message Digest Algorithm used : " + hashAlgorithm);
		System.out.println("Digital Signature Algorithm used :"
				+ signingAlgorithm);
		String autackMessage = EDIFACTMessageProcessor
				.generateAUTACKMessageBlockForBarclays(myMessage, privateKey,
						hashAlgorithm, signingAlgorithm, messageWayKeyId,
						customerName, interchangeControlReference, false);
		
		System.out.println("----BEGIN--EDIFACT AUTACK BLOCK -----");
		System.out.println(autackMessage);
		System.out.println("----END----EDIFACT AUTACK BLOCK -----");

		/**
		 * Create the digital signed file.
		 */
		File digitallySignedEdifactPaymentFile = new File(
				paymentFile.getCanonicalFile() + ".DSF");
		createDigitallySignedFileData(edifactPaymentFileData, autackMessage,
				digitallySignedEdifactPaymentFile);
		System.out.println("Digitally signed file is ->"
				+ digitallySignedEdifactPaymentFile.getCanonicalPath());
	}

	/**
	 * This method will return a StringBuilder object containing the all data in
	 * the PAYMENT file to be signed.
	 * 
	 * @param paymentFile
	 * @return
	 * @throws IOException
	 */
	private static final StringBuilder getContentOfFile(File paymentFile)
			throws IOException {
		BufferedReader br = new BufferedReader(new FileReader(paymentFile));
		StringBuilder sb = new StringBuilder();

		while (true) {
			String line = br.readLine();

			if (line == null) {
				break;
			} else {
				sb.append(line);
			}
		}
		br.close();
		return sb;
	}

	private static final String getInterchangeControlReference(
			StringBuilder paymentData) throws IOException {

		int indexUNB = paymentData.indexOf("UNB");
		int indexFirstSegmentDelimeter = paymentData.indexOf("'", indexUNB);
		StringBuilder sb = new StringBuilder(paymentData.substring(indexUNB,
				indexFirstSegmentDelimeter));

		StringTokenizer st = new StringTokenizer(sb.toString(), "+");
		String token[] = new String[6];
		for (int i = 0; i < 6; i++) {
			if (st.hasMoreTokens()) {
				token[i] = st.nextToken();
			}
		}
		// The interchange reference number is the 6th Segment in the UNB group.
		return token[5];
	}

	private static final String getCustomerName(StringBuilder paymentData)
			throws IOException {

		int indexUNB = paymentData.indexOf("UNB");
		int indexFirstSegmentDelimeter = paymentData.indexOf("'", indexUNB);
		StringBuilder sb = new StringBuilder(paymentData.substring(indexUNB,
				indexFirstSegmentDelimeter));

		StringTokenizer st = new StringTokenizer(sb.toString(), "+");
		String token[] = new String[3];
		for (int i = 0; i < 3; i++) {
			if (st.hasMoreTokens()) {
				token[i] = st.nextToken();
			}
		}
		// The interchange reference number is the 6th Segment in the UNB group.
		return token[2];
	}

	private static final StringBuilder getContentToBeSigned(
			StringBuilder paymentFileData) throws IOException {
		StringBuilder dataToBeSigned = new StringBuilder();
		dataToBeSigned.append(paymentFileData.toString());

		/**
		 * Carry out operation to remove the EDIFACT File Header and Footer
		 */
		int indexUNB = dataToBeSigned.indexOf("UNB");
		if (indexUNB >= 0) {
			int indexFirstSegmentDelimeter = dataToBeSigned.indexOf("'",
					indexUNB);
			dataToBeSigned.delete(indexUNB, indexFirstSegmentDelimeter + 1);
			int indexUNZ = dataToBeSigned.indexOf("UNZ");
			dataToBeSigned.delete(indexUNZ, dataToBeSigned.length());
		}
		return dataToBeSigned;
	}

	private static final void printHelperMessage() {
		// automatically generate the help statement
		HelpFormatter formatter = new HelpFormatter();
		System.out.println();
		StringBuilder footer = new StringBuilder();

		ArrayList<String> allowedMessageDigestAlgorithm = new ArrayList<String>(
				X509DigitalSigning.getAllowedMessageDigestAlgorithm().values());
		ArrayList<String> allowedSignatureAlgorithm = new ArrayList<String>(
				X509DigitalSigning.getAllowedSignatureAlgorithm().values());
		footer.append("\nThe allowed Message Digest algorithms :\n ");
		for (int i = 0; i < allowedMessageDigestAlgorithm.size(); i++) {
			if (i == allowedMessageDigestAlgorithm.size() - 1) {
				footer.append(" and " + allowedMessageDigestAlgorithm.get(i));
			} else {
				footer.append(allowedMessageDigestAlgorithm.get(i));
			}
			if (allowedMessageDigestAlgorithm.size() > 1) {
				if (allowedMessageDigestAlgorithm.size() > 0
						&& (i < allowedMessageDigestAlgorithm.size() - 2)) {
					footer.append(", ");
				}
			}
		}
		footer.append(".");
		footer.append("\nThe allowed Signature agorithms :\n ");
		for (int i = 0; i < allowedSignatureAlgorithm.size(); i++) {
			if (i == allowedSignatureAlgorithm.size() - 1) {
				footer.append(" and " + allowedSignatureAlgorithm.get(i));
			} else {
				footer.append(allowedSignatureAlgorithm.get(i));
			}
			if (allowedSignatureAlgorithm.size() > 1) {
				if (allowedSignatureAlgorithm.size() > 0
						&& (i < allowedSignatureAlgorithm.size() - 2)) {
					footer.append(", ");
				}
			}
		}
		footer.append(".\n");

		formatter.printHelp(132, DigitalSigningCmd.class.getName(), "",
				options, footer.toString(), true);
	}

	private static final void createDigitallySignedFileData(
			StringBuilder orgPaymentFileData, String autack,
			File digitallySignedFile) throws IOException {
		StringBuilder digSignedPaymentFileData = new StringBuilder();
		digSignedPaymentFileData.append(orgPaymentFileData.substring(0,
				orgPaymentFileData.indexOf("UNZ")));
		digSignedPaymentFileData.append(autack);
		digSignedPaymentFileData
				.append(orgPaymentFileData.subSequence(
						orgPaymentFileData.indexOf("UNZ"),
						orgPaymentFileData.length()));

		StringTokenizer st = new StringTokenizer(
				digSignedPaymentFileData.toString(), "'");
		StringBuilder formattedDigSignedData = new StringBuilder();
		while (st.hasMoreTokens()) {
			formattedDigSignedData.append(st.nextToken());
			formattedDigSignedData.append("'\n");
		}

		BufferedWriter bw = new BufferedWriter(new FileWriter(
				digitallySignedFile));
		bw.write(formattedDigSignedData.toString());
		bw.close();
	}

}
