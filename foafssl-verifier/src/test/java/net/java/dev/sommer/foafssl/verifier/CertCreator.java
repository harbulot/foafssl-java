/*
 Copyright (c) 2009, The University of Manchester, United Kingdom.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the The University of Manchester nor the names of
      its contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

  Author: Bruno Harbulot
  Author: Henry Story
 */

package net.java.dev.sommer.foafssl.verifier;

import net.java.dev.sommer.foafssl.principals.X509Claim;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.misc.NetscapeCertType;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;
import sun.security.rsa.RSAPublicKeyImpl;

import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Vector;
import java.util.logging.Logger;

/**
 * Creates a certificate. Useful for debugging.
 * <p/>
 * This class was taken from xwiki CertGen class. It is clear that this should be refactored a little bit,
 * and placed in a library
 *
 * @author Henry Story
 */

public class CertCreator {
    static final String issuer = "O=FOAF\\+SSL, OU=The Community of Self Signers, CN=Not a Certification Authority"; //the exact name for the FOAF+SSL issuer is still being decided

    static transient Logger log = Logger.getLogger(X509Claim.class.getName());
    String webId;
    String CN;
    Date startDate;
    Date endDate;
    int durationInDays;
    float durationInHours;
    PublicKey subjectPubKey;
    BigInteger modulus = new BigInteger("d2hda8ngk98t8gunqbho6eo0m9m0icsig5ib9pjdqjg8k11cpdq72vkv3s3p9ifebeu7q106c95" +
            "bel6nrvd9fb64lu4btdtchouuvl2emc9fchcf75a5ns9cmq98h5q8pd5h8o57jnlc1aamc7ee98nelli3gg1kg93t" +
            "n81vapoprqc0bn2jnl10ti5da1gu7buosk14fqeet", 32);

    PrivateKey issuerPrivateKey;
    PublicKey issuerPubKey;

    X509Certificate cert = null;
    static SecureRandom numberGenerator;
    X509Name issuerDN;

    CertCreator() throws InvalidKeyException {
        issuerPubKey = new RSAPublicKeyImpl( modulus, new BigInteger("65536"));
        issuerPrivateKey = new RSAPrivateKeyImpl(
                modulus,
                new BigInteger("60u1fqk2d4gjbascjcnrnu001cvtggg8s19gufa62oheg752imlni0hoq7p0jee8g95n52evee127notk2" +
                        "cc1o58pq74ft4tnfs7mj65bltgnji8t30v79uorpcbiqcj2pmu69q1l3chult0frhtrok197jku19jdgcprjvngtd" +
                        "sflnjlgoopo5dbvc10c96g1li4pd661q71", 32)
        );
    }


    /**
     * partly taken from UUID class. Generates random numbers
     *
     * @return a UUID BigInteger
     */
    BigInteger nextRandom() {
        SecureRandom ng = numberGenerator;
        if (ng == null) {
            numberGenerator = ng = new SecureRandom();
        }

        byte[] randomBytes = new byte[16];
        ng.nextBytes(randomBytes);
        return new BigInteger(randomBytes).abs();
    }

    public X509Certificate getCertificate() {
        return cert;
    }


    public void setSubjectWebID(String urlStr) {
        try {
            URL url = new URL(urlStr);
            String protocol = url.getProtocol();
            if (protocol.equals("http") || protocol.equals("https") || protocol.equals("ftp") || protocol.equals("ftps")) {
                //everything probably ok, though really https should be the default
            } else {
                //could very well be a mistake
                log.warning("using WebId with protocol " + protocol + ". Could be a mistake. WebId=" + url);
            }

        } catch (MalformedURLException e) {
            e.printStackTrace();
        }
        this.webId = urlStr;
    }

    public void setSubjectCommonName(String name) {
        CN = name;
    }

    public void setStartDate(Date startDate) {
        this.startDate = startDate;
    }

    public void setEndDate(Date endDate) {
        this.endDate = endDate;
    }


    public void addDurationInDays(String days) {
        try {
            Float d = Float.valueOf(days);
            this.durationInDays += d.intValue();
            float remainder = (d - durationInDays);
            this.durationInHours += remainder * 24;
        } catch (NumberFormatException e) {
            log.warning("unable to interpret the number of days passed as a float " + days);
        }
        //this.durationInDays = days;
    }

    public void addDurationInHours(String hours) {
        try {
            this.durationInHours = Float.valueOf(hours);
        } catch (NumberFormatException e) {
            log.warning("unable to interpret the number of hours passed as a float" + hours);
        }
    }

    public PublicKey getSubjectPublicKey() {
        return subjectPubKey;
    }

    /**
     * Set the <a href="http://en.wikipedia.org/wiki/Spkac">Spkac</a> data sent by browser
     * One should set either this or the pemCSR.
     *
     * @param pubkey the public key for the subject
     */
    void setSubjectPublicKey(PublicKey pubkey) {
        this.subjectPubKey = pubkey;
    }


    protected void generate() throws Exception {
        X509V3CertificateGenerator certGenerator = new X509V3CertificateGenerator();

        certGenerator.reset();
        /*
         * Sets up the subject distinguished name. Since it's a self-signed
         * certificate, issuer and subject are the same.
         */
        certGenerator.setIssuerDN(new X509Name(issuer));


        Vector<DERObjectIdentifier> subjectDnOids = new Vector<DERObjectIdentifier>();
        Vector<String> subjectDnValues = new Vector<String>();

        subjectDnOids.add(X509Name.O);
        subjectDnValues.add("FOAF+SSL");
        subjectDnOids.add(X509Name.OU);
        subjectDnValues.add("The Community Of Self Signers");
        subjectDnOids.add(X509Name.UID);
        subjectDnValues.add(webId);
        subjectDnOids.add(X509Name.CN);
        subjectDnValues.add(CN);

        X509Name DName = new X509Name(subjectDnOids, subjectDnValues);
        certGenerator.setSubjectDN(DName);

        /*
         * Sets up the validity dates.
         */
        certGenerator.setNotBefore(getStartDate());

        certGenerator.setNotAfter(getEndDate());

        /*
         * The serial-number of this certificate is 1. It makes sense because
         * it's self-signed.
         */
        certGenerator.setSerialNumber(nextRandom());

        /*
         * Sets the public-key to embed in this certificate.
         */
        certGenerator.setPublicKey(subjectPubKey);
        /*
         * Sets the signature algorithm.
         */
//        String pubKeyAlgorithm = service.caPubKey.getAlgorithm();
//        if (pubKeyAlgorithm.equals("DSA")) {
//            certGenerator.setSignatureAlgorithm("SHA1WithDSA");
//        } else if (pubKeyAlgorithm.equals("RSA")) {
        certGenerator.setSignatureAlgorithm("SHA1WithRSAEncryption");
//        } else {
//            RuntimeException re = new RuntimeException(
//                    "Algorithm not recognised: " + pubKeyAlgorithm);
//            LOGGER.error(re.getMessage(), re);
//            throw re;
//        }

        /*
         * Adds the Basic Constraint (CA: false) extension.
         */
        certGenerator.addExtension(X509Extensions.BasicConstraints, true,
                new BasicConstraints(false));

        /*
         * Adds the Key Usage extension.
         */
        certGenerator.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(
                KeyUsage.digitalSignature | KeyUsage.nonRepudiation
                        | KeyUsage.keyEncipherment | KeyUsage.keyAgreement
                        | KeyUsage.keyCertSign));

        /*
         * Adds the Netscape certificate type extension.
         */
        certGenerator.addExtension(MiscObjectIdentifiers.netscapeCertType,
                false, new NetscapeCertType(NetscapeCertType.sslClient
                        | NetscapeCertType.smime));

        /*
         * Adds the authority key identifier extension.
         * Bruno pointed out that this is not needed, as the authority's key is never checked in this setup!
         * so I am commenting it out, to be removed at a later date.
         *

        AuthorityKeyIdentifierStructure authorityKeyIdentifier;
        try {
            authorityKeyIdentifier = new AuthorityKeyIdentifierStructure(
                    service.certificate.getPublicKey());
        } catch (InvalidKeyException e) {
            throw new Exception("failed to parse CA cert. This should never happen", e);
        }

        certGenerator.addExtension(X509Extensions.AuthorityKeyIdentifier,
                false, authorityKeyIdentifier);
        */

        /*
         * Adds the subject key identifier extension.
         */
        SubjectKeyIdentifier subjectKeyIdentifier = new SubjectKeyIdentifierStructure(
                subjectPubKey);
        certGenerator.addExtension(X509Extensions.SubjectKeyIdentifier, false,
                subjectKeyIdentifier);

        /*
         * Adds the subject alternative-name extension (critical).
         */
        if (webId != null) {
            GeneralNames subjectAltNames = new GeneralNames(new GeneralName(
                    GeneralName.uniformResourceIdentifier, webId));
            certGenerator.addExtension(X509Extensions.SubjectAlternativeName,
                    true, subjectAltNames);
        } else throw new Exception("WebId not set!");

        /*
         * Creates and sign this certificate with the private key corresponding
         * to the public key of the FOAF+SSL DN
         */
        cert = certGenerator.generate(issuerPrivateKey);

        /*
         * Checks that this certificate has indeed been correctly signed.
         * No need nobody will verify, but anyway...
         */
        //todo: does not work for some reason... I get: java.security.InvalidKeyException: Public key presented not for certificate signature
      //  cert.verify(issuerPubKey);

    }

    public Date getEndDate() {
        if (endDate == null) {
            long endtime;
            if (durationInDays != 0 || durationInHours != 0) {
                endtime = getStartDate().getTime();
                endtime += durationInDays * 24 * 60 * 60 * 1000 + (long) (durationInHours * 60 * 60 * 1000);
            } else {
                endtime = startDate.getTime() + 365L * 24L * 60L * 60L * 1000L;
            }
            endDate = new Date(endtime);
        }
        return endDate;
    }


    public Date getStartDate() {
        if (startDate == null) {
            startDate = new Date();
        }
        return startDate;
    }

}
