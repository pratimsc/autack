package com.maikalal.autack.ifs.test;

import java.io.IOException;
import java.security.*;
import java.security.cert.*;
import java.util.Collections;
import java.util.Iterator;

import org.bouncycastle.cms.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;

import sun.security.pkcs.PKCS7;
import sun.security.pkcs.ParsingException;

public class TPKCS7Data {

	private static final String ROOT_ALIAS = null;

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		Security.addProvider(new BouncyCastleProvider());
		String signedData =
		 "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";
		try {
			CMSSignedDataParser cdp = new CMSSignedDataParser(Base64.decode(signedData));
			CMSTypedStream cmsStream =  cdp.getSignedContent();
			
			PKCS7 pkcs7 = new PKCS7(cmsStream.getContentStream());
			
			X509Certificate prevCert = null; // Previous certificate we've found
			X509Certificate[] certs = pkcs7.getCertificates(); // `java.security.cert.X509Certificate`
			
			
			for (int i = 0; i < certs.length; i++) {
			    // *** Checking certificate validity period here

			    if (prevCert != null) {
			        // Verify previous certificate in chain against this one
			        prevCert.verify(certs[i].getPublicKey());
			    }
			    prevCert = certs[i];
			}
			
		} catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException | CMSException | IOException e) {
			e.printStackTrace();
		}

	}
	
	private static boolean verifyData(KeyStore keyStore, CMSSignedData signed)
            throws Exception {
        // verification step
        X509Certificate rootCert = (X509Certificate) keyStore
                .getCertificate(ROOT_ALIAS);

        if (isValidSignature(signed, rootCert)) {
            System.out.println("verification succeeded");
            return true;
        } else {
            System.out.println("verification failed");
        }
        return false;
    }
	
	/**
     * Take a CMS SignedData message and a trust anchor and determine if the
     * message is signed with a valid signature from a end entity entity
     * certificate recognized by the trust anchor rootCert.
     */
    private static boolean isValidSignature(CMSSignedData signedData,
            X509Certificate rootCert) throws Exception {

        boolean[] bArr = new boolean[2];
        bArr[0] = true;
        CertStore certsAndCRLs = signedData.getCertificatesAndCRLs(
                "Collection", "BC");
        SignerInformationStore signers = signedData.getSignerInfos();
        Iterator it = signers.getSigners().iterator();

        if (it.hasNext()) {
            SignerInformation signer = (SignerInformation) it.next();
            SignerId signerConstraints = signer.getSID();
            signerConstraints.setKeyUsage(bArr);
            PKIXCertPathBuilderResult result = buildPath(rootCert,
                    signer.getSID(), certsAndCRLs);
            return signer.verify(result.getPublicKey(), "BC");
        }

        return false;
    }

    /**
     * Build a path using the given root as the trust anchor, and the passed in
     * end constraints and certificate store.
     * <p>
     * Note: the path is built with revocation checking turned off.
     */
    public static PKIXCertPathBuilderResult buildPath(X509Certificate rootCert,
            X509CertSelector endConstraints, CertStore certsAndCRLs)
            throws Exception {
        CertPathBuilder builder = CertPathBuilder.getInstance("PKIX", "BC");
        PKIXBuilderParameters buildParams = new PKIXBuilderParameters(
                Collections.singleton(new TrustAnchor(rootCert, null)),
                endConstraints);

        buildParams.addCertStore(certsAndCRLs);
        buildParams.setRevocationEnabled(false);

        return (PKIXCertPathBuilderResult) builder.build(buildParams);
    }

}
