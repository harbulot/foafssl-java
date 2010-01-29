/**-----------------------------------------------------------------------
  
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

  Author........: Bruno Harbulot

-----------------------------------------------------------------------*/
package uk.ac.manchester.rcs.bruno.samlredirector.idp;

import static org.junit.Assert.*;

import java.io.InputStream;
import java.lang.Thread.UncaughtExceptionHandler;
import java.net.URI;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Collections;
import java.util.Enumeration;

import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.joda.time.DateTime;
import org.junit.Test;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Response;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.BasicCredential;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.validation.ValidationException;
import org.w3c.dom.Element;

import uk.ac.manchester.rcs.bruno.samlredirector.common.SamlAuthnResponseBuilder;

/**
 * @author Bruno Harbulot (Bruno.Harbulot@manchester.ac.uk)
 * 
 */
public class SamlAuthnResponseBuilderTest {
    public final static String CERTIFICATES_DIRECTORY = "org/jsslutils/certificates/";
    public final static String KEYSTORE_PASSWORD_STRING = "testtest";
    public final static char[] KEYSTORE_PASSWORD = KEYSTORE_PASSWORD_STRING.toCharArray();

    private static final String TEST_SP_URI = "http://sp.example.org/sp/";
    private static final String TEST_IDP_URI = "http://idp.example.org/idp/";
    private static final String TEST_ID_URI = "http://foaf.example.com/bruno/#me";

    /**
     * Loads the 'localhost' keystore from the test keystore.
     * 
     * @return test keystore.
     * @throws Exception
     */
    public KeyStore getKeyStore() throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        InputStream ksis = ClassLoader.getSystemResourceAsStream(CERTIFICATES_DIRECTORY
                + "localhost.p12");
        ks.load(ksis, KEYSTORE_PASSWORD);
        ksis.close();
        return ks;
    }

    public PublicKey getPublicKey() throws Exception {
        KeyStore keyStore = getKeyStore();
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (keyStore.isKeyEntry(alias)) {
                return keyStore.getCertificate(alias).getPublicKey();
            }
        }
        return null;
    }

    public PrivateKey getPrivateKey() throws Exception {
        KeyStore keyStore = getKeyStore();
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (keyStore.isKeyEntry(alias)) {
                return (PrivateKey) keyStore.getKey(alias, KEYSTORE_PASSWORD);
            }
        }
        return null;
    }

    public void testSignature(Credential signingCredential, final Credential verifyingCredential)
            throws Throwable {
        DateTime dateTime = new DateTime(500000);

        final Response samlResponse = SamlAuthnResponseBuilder.getInstance()
                .buildSubjectAuthenticatedAssertion(URI.create(TEST_IDP_URI),
                        Collections.singletonList(URI.create(TEST_SP_URI)),
                        URI.create(TEST_ID_URI), signingCredential, dateTime);

        assertNotNull(samlResponse);

        /*
         * Verifies the signature.
         */
        assertNotNull("Signed response? ", samlResponse.getSignature());
        Thread th = new Thread() {
            public void run() {
                try {
                    SAMLSignatureProfileValidator signatureProfileValidator = new SAMLSignatureProfileValidator();
                    signatureProfileValidator.validate(samlResponse.getSignature());

                    SignatureValidator signatureValidator = new SignatureValidator(
                            verifyingCredential);
                    Signature signature = samlResponse.getSignature();
                    signatureValidator.validate(signature);
                } catch (ValidationException e) {
                    e.printStackTrace();
                    throw new RuntimeException(e);
                }
            }
        };
        UncaughtExceptionHandlerImpl exHandler = new UncaughtExceptionHandlerImpl();
        th.setUncaughtExceptionHandler(exHandler);
        th.start();
        th.join();
        if (exHandler.getThrowable() != null) {
            throw exHandler.getThrowable();
        }
        
        /*
         * Tests the response.
         */
        assertNotNull(samlResponse.getAssertions());
        assertEquals(1, samlResponse.getAssertions().size());
        final Assertion samlAssertion = samlResponse.getAssertions().get(0);

        samlAssertion.detach();
        /*
         * Displays the response as XML.
         */
        MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
        Marshaller marshaller = marshallerFactory.getMarshaller(samlAssertion);
        Element responseElement = marshaller.marshall(samlAssertion);
        System.out.println();
        TransformerFactory tFactory = TransformerFactory.newInstance();
        Transformer t = tFactory.newTransformer();
        Source xmlSource = new DOMSource(responseElement);
        StreamResult streamResult = new StreamResult(System.out);
        t.transform(xmlSource, streamResult);
        System.out.println();
        System.out.println();

        assertNotNull(samlAssertion);
        assertNotNull(samlAssertion.getSubject());
        assertNotNull(samlAssertion.getSubject().getNameID());
        // assertEquals("... some format ...", responseAssertion.getSubject()
        // .getNameID().getFormat());
        assertEquals(TEST_ID_URI, samlAssertion.getSubject().getNameID().getValue());
        assertNotNull(samlAssertion.getAuthnStatements());
        assertEquals(1, samlAssertion.getAuthnStatements().size());
        AuthnStatement samlAuthnStatement = samlAssertion.getAuthnStatements().get(0);
        DateTime authnTime = samlAuthnStatement.getAuthnInstant();
        assertTrue(authnTime.compareTo(dateTime) == 0);
    }

    public static class UncaughtExceptionHandlerImpl implements UncaughtExceptionHandler {
        private volatile Throwable throwable = null;

        @Override
        public void uncaughtException(Thread t, Throwable e) {
            this.throwable = e;
        }

        public Throwable getThrowable() {
            return this.throwable;
        }
    }

    @Test
    public void testSameBasicCredential() throws Throwable {
        BasicCredential basicCred = new BasicCredential();
        basicCred.setPrivateKey(getPrivateKey());
        basicCred.setPublicKey(getPublicKey());
        testSignature(basicCred, basicCred);
    }

    @Test
    public void testDistinctBasicCredential() throws Throwable {
        BasicCredential signingCred = new BasicCredential();
        signingCred.setPrivateKey(getPrivateKey());
        signingCred.setPublicKey(getPublicKey());
        BasicCredential verifyingCred = new BasicCredential();
        verifyingCred.setPublicKey(getPublicKey());
        verifyingCred.setPrivateKey(getPrivateKey());
        testSignature(signingCred, verifyingCred);
    }

    @Test
    public void testSecHelperCredential() throws Throwable {
        Credential signingCred = SecurityHelper
                .getSimpleCredential(getPublicKey(), getPrivateKey());
        testSignature(signingCred, signingCred);
    }
}
