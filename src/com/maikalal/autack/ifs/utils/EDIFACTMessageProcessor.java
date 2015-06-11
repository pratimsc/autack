package com.maikalal.autack.ifs.utils;

import java.nio.charset.Charset;
import java.security.*;
import java.sql.Date;
import java.util.*;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.time.DateFormatUtils;

public final class EDIFACTMessageProcessor {
	public final static String HASH_ALGORITHM_MD2 = "MD2";
	public final static String HASH_ALGORITHM_MD5 = "MD5";
	public final static String HASH_ALGORITHM_SHA1 = "SHA-1";
	public final static String HASH_ALGORITHM_SHA256 = "SHA-256";
	public final static String HASH_ALGORITHM_SHA384 = "SHA-384";
	public final static String HASH_ALGORITHM_SHA512 = "SHA-512";

	private static HashMap<String, String> getAlgorithmTable() {
		HashMap<String, String> algorithm = new HashMap<String, String>();
		algorithm.put(HASH_ALGORITHM_MD2.toUpperCase(), "5");
		algorithm.put(HASH_ALGORITHM_MD5.toUpperCase(), "6");
		algorithm.put(HASH_ALGORITHM_SHA1.toUpperCase(), "16");
		algorithm.put(HASH_ALGORITHM_SHA256.toUpperCase(), "48");
		algorithm.put(HASH_ALGORITHM_SHA384.toUpperCase(), "50");
		algorithm.put(HASH_ALGORITHM_SHA512.toUpperCase(), "49");
		return algorithm;
	}

	private EDIFACTMessageProcessor() {
		// Do not allow creation of an instance as this is a Utility class
	}

	public static String generateAUTACKMessageBlockForBarclays(
			String aDataBlock, PrivateKey aPrivateKey,
			String aHashingAlgorithm, String aDigitalSigningAlgorithm,
			String aCertificateReferenceInMessageWay,
			String anInterchangeSenderCustomerName,
			String anInterchangeControlReference,
			boolean createMultiLineAutackMessage)
			throws NoSuchAlgorithmException, InvalidKeyException,
			SignatureException, NoSuchProviderException {
		// Get the HASHED value of the data
		byte[] messageHashedByte = X509DigitalSigning
				.createHashSignatureOfData(
						aDataBlock.getBytes(Charset.forName("US-ASCII")),
						aHashingAlgorithm);
		System.out.println("Hash value of the data to be signed in HEX :\n"+Hex.encodeHexString(messageHashedByte));

		byte[] signedMessageByte = X509DigitalSigning
				.createDigitalSignatureOfData(messageHashedByte,
						aDigitalSigningAlgorithm, aPrivateKey);
		System.out.println("Signed value of the data to be signed in HEX :\n"+Hex.encodeHexString(signedMessageByte));

		Date signingDate = new Date(Calendar.getInstance().getTimeInMillis());

		// AUTACK Message
		StringBuilder autackMessage = new StringBuilder();

		// Build UNH
		autackMessage.append("UNH+1+AUTACK:4:1:UN:APACS'");
		if (createMultiLineAutackMessage)
			autackMessage.append("\n");
		// Build UNH
		autackMessage.append("USH+7+1+3+1+2+1+1++++1:");
		autackMessage.append(DateFormatUtils.format(signingDate, "yyyyMMdd"));
		autackMessage.append(":");
		autackMessage.append(DateFormatUtils.format(signingDate, "HHmmss"));
		autackMessage.append("'");
		if (createMultiLineAutackMessage)
			autackMessage.append("\n");
		// Build USA
		autackMessage.append("USA+1:16:1:");
		autackMessage.append(getAlgorithmTable().get(
				aHashingAlgorithm.toUpperCase()));
		autackMessage.append(":1'");
		if (createMultiLineAutackMessage)
			autackMessage.append("\n");
		// Build USC
		autackMessage.append("USC+");
		autackMessage.append(aCertificateReferenceInMessageWay);
		autackMessage.append("+4::BARCLAYS:1:1'");
		if (createMultiLineAutackMessage)
			autackMessage.append("\n");
		// Build USB +TEST_IFS_TO+BARCLAYS BANK'
		autackMessage.append("USB+1+5:");
		autackMessage.append(DateFormatUtils.format(signingDate, "yyyyMMdd"));
		autackMessage.append(":");
		autackMessage.append(DateFormatUtils.format(signingDate, "HHmmss"));
		autackMessage.append("+");
		autackMessage.append(anInterchangeSenderCustomerName);
		autackMessage.append("+BARCLAYS BANK'");
		if (createMultiLineAutackMessage)
			autackMessage.append("\n");
		// Build USX
		autackMessage.append("USX+");
		autackMessage.append(anInterchangeControlReference);
		autackMessage.append("'");
		if (createMultiLineAutackMessage)
			autackMessage.append("\n");
		// Build USY
		autackMessage.append("USY+1+1:");
		autackMessage.append(Hex.encodeHex(signedMessageByte, false));
		autackMessage.append("'");
		if (createMultiLineAutackMessage)
			autackMessage.append("\n");
		// Build UST
		autackMessage.append("UST+1+4'");
		if (createMultiLineAutackMessage)
			autackMessage.append("\n");
		// Build UNT
		autackMessage.append("UNT+9+1'");
		if (createMultiLineAutackMessage)
			autackMessage.append("\n");
		return autackMessage.toString();
	}
}
