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
package net.java.dev.sommer.foafssl.login;

import static org.junit.Assert.*;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.net.URLStreamHandlerFactory;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Enumeration;
import java.util.Properties;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NameNotFoundException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.util.encoders.Base64;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mortbay.jetty.servlet.ServletHolder;
import org.mortbay.jetty.testing.HttpTester;
import org.mortbay.jetty.testing.ServletTester;
import org.restlet.data.Form;
import org.restlet.data.Parameter;
import org.restlet.data.Reference;

/**
 * @author Bruno Harbulot (Bruno.Harbulot@manchester.ac.uk)
 */
public class IdpServletCustomResponseTest {
    public final static String CERTIFICATES_DIRECTORY = "org/jsslutils/certificates/";
    public final static String KEYSTORE_PASSWORD_STRING = "testtest";
    public final static char[] KEYSTORE_PASSWORD = KEYSTORE_PASSWORD_STRING.toCharArray();

    private static final String TEST_IDP_KEYNAME = "http://idp.example.org/idp/#pubkey";
    private static final String TEST_IDP_URI = "http://idp.example.org/idp/";
    private static final String TEST_SP_URI = "http://sp.example.com/sp/";

    public static final String TEST_FOAF_FILENAME = "dummy-foaf.rdf.xml";
    public static final String TEST_CERT_FILENAME = "dummy-foafsslcert.pem";
    public static final String TEST_WEBID = "http://foaf.example.net/bruno#me";

    private ServletTester idpServletTester;

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

    /**
     * Returns the public key matching the private key used to sign the
     * assertion.
     * 
     * @return public key matching the private key used to sign the assertion.
     * @throws Exception
     */
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

    /**
     * Sets up the servlet tester, loads the keystore and passes the appropriate
     * parameters.
     * 
     * @throws Exception
     */
    @Before
    public void setUp() throws Exception {
        /*
         * Passes the keystore via JNDI to the servlet.
         */
        Context ctx = null;
        try {
            Properties props = new Properties();
            props.setProperty(Context.INITIAL_CONTEXT_FACTORY,
                    "org.mortbay.naming.InitialContextFactory");
            ctx = (Context) new InitialContext(props).lookup("java:comp");
            try {
                ctx = (Context) ctx.lookup("env");
            } catch (NameNotFoundException e) {
                ctx = ctx.createSubcontext("env");
            }
            try {
                ctx = (Context) ctx.lookup("keystore");
            } catch (NameNotFoundException e) {
                ctx = ctx.createSubcontext("keystore");
            }
            ctx.rebind("signingKeyStore", getKeyStore());
        } finally {
            if (ctx != null) {
                ctx.close();
            }
        }

        /*
         * Creates a mock URLConnection not to make outside connections to
         * de-reference the FOAF file for the tests.
         */
        URLStreamHandlerFactory mockStreamHandlerFactory = new URLStreamHandlerFactory() {
            public URLStreamHandler createURLStreamHandler(String protocol) {
                if ("http".equals(protocol) || "https".equals(protocol)) {
                    return new URLStreamHandler() {
                        @Override
                        protected URLConnection openConnection(URL u) throws IOException {
                            return new HttpURLConnection(u) {
                                @Override
                                public void disconnect() {
                                }

                                @Override
                                public boolean usingProxy() {
                                    return false;
                                }

                                @Override
                                public void connect() throws IOException {
                                }

                                @Override
                                public String getContentType() {
                                    return "application/rdf+xml";
                                }

                                @Override
                                public InputStream getInputStream() throws IOException {
                                    return IdpServletCustomResponseTest.class
                                            .getResourceAsStream(TEST_FOAF_FILENAME);
                                }
                            };
                        }
                    };
                }
                return null;
            }
        };
        try {
            URL.setURLStreamHandlerFactory(mockStreamHandlerFactory);
        } catch (Throwable e) {
        }

        /*
         * Creates the servlet tester.
         */
        idpServletTester = new ServletTester();
        idpServletTester.setContextPath("/idp");
        ServletHolder servletHolder = idpServletTester.addServlet(IdpServlet.class, "/*");
        servletHolder.setInitParameter("keyPassword", KEYSTORE_PASSWORD_STRING);
        servletHolder.setInitParameter("issuerName", TEST_IDP_URI);
        servletHolder.setInitParameter("keyName", TEST_IDP_KEYNAME);
        idpServletTester.start();
    }

    @Test
    public void testRequest() throws Exception {
        /*
         * Creates a fake simple authn request.
         */
        Reference authnReqResourceRef = new Reference(TEST_IDP_URI);
        authnReqResourceRef.addQueryParameter(IdpServlet.AUTHREQISSUER_PARAMNAME, TEST_SP_URI);

        /*
         * Sets up the request in the Jetty tester. The URL to which to send the
         * simple authn request is modelled by authnReqResourceRef.
         */
        HttpTester request = new HttpTester();
        HttpTester response = new HttpTester();
        request.setHeader("Host", authnReqResourceRef.getHostDomain());
        request.setMethod("GET");
        String authReqUrlQueryPart = authnReqResourceRef.getQuery();
        request.setURI(authnReqResourceRef.getPath()
                + (authReqUrlQueryPart != null ? "?" + authReqUrlQueryPart : ""));

        /*
         * Fakes the presence of a client certificate.
         */
        idpServletTester.addFilter(FakeClientCertInsertionFilter.class, "/*", 0);

        /*
         * Performs the request.
         */
        response.parse(idpServletTester.getResponses(request.generate()));

        System.out.println("Request URI: " + authnReqResourceRef.toString());
        System.out.println("Response status: " + response.getStatus());
        String location = response.getHeader("Location");
        System.out.println("Response Location header: " + location);
        System.out.println("Response Location header length: " + location.length());
        System.out.println();

        /*
         * Process the response.
         */
        Reference authnRespResourceRef = new Reference(location);
        Form authnRespResourceRefQueryForm = authnRespResourceRef.getQueryAsForm();

        /*
         * Tries to verify the signature, if present.
         */
        String authnUriParam = authnRespResourceRefQueryForm
                .getFirstValue(IdpServlet.WEBID_PARAMNAME);
        String authnDateTimeParam = authnRespResourceRefQueryForm
                .getFirstValue(IdpServlet.TIMESTAMP_PARAMNAME);
        String sigAlgParam = authnRespResourceRefQueryForm
                .getFirstValue(IdpServlet.SIGALG_PARAMNAME);
        Parameter signatureParam = authnRespResourceRefQueryForm
                .getFirst(IdpServlet.SIGNATURE_PARAMNAME);

        assertNotNull("Signature?", signatureParam);

        authnRespResourceRefQueryForm.remove(signatureParam);

        authnRespResourceRef.setQuery(null);
        for (Parameter param : authnRespResourceRefQueryForm) {
            authnRespResourceRef.addQueryParameter(param.getName(), param.getValue());
        }
        String signedMessage = authnRespResourceRef.toString();
        System.out.println("SignedMessage: " + signedMessage);

        byte[] signatureBytes = Base64.decode(signatureParam.getValue());
        String sigAlg = null;
        if ("dsa-sha1".equals(sigAlgParam)) {
            sigAlg = "SHA1withDSA";
        } else if ("rsa-sha1".equals(sigAlgParam)) {
           sigAlg = "SHA1withRSA";
        } else {
            fail("Unsupported signature algorithm.");
        }
        Signature signature = Signature.getInstance(sigAlg);
        signature.initVerify(getPublicKey());
        signature.update(signedMessage.getBytes());
        assertTrue("Signature verified?", signature.verify(signatureBytes));

        assertEquals("ID verified?", TEST_WEBID, authnUriParam);

        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ");
        Date authnDate = dateFormat.parse(authnDateTimeParam);
        assertTrue("Authn date in the past?", authnDate.before(new Date()));
        assertTrue("Authn date no older than 5s?", authnDate.after(new Date(System
                .currentTimeMillis() - 5000)));
    }

    @After
    public void tearDown() throws Exception {
        if (idpServletTester != null) {
            idpServletTester.stop();
        }
    }

    /**
     * 
     * This filter is used for the test: it fakes the presence of a client
     * certificate in the request.
     * 
     * @author Bruno Harbulot.
     * 
     */
    public static class FakeClientCertInsertionFilter implements Filter {
        static {
            Security.addProvider(new BouncyCastleProvider());
        }
        private X509Certificate x509Certificate;

        public void destroy() {
        }

        public void doFilter(ServletRequest request, ServletResponse response, FilterChain next)
                throws IOException, ServletException {
            request.setAttribute("javax.servlet.request.X509Certificate",
                    new X509Certificate[] { x509Certificate });
            next.doFilter(request, response);
        }

        public void init(FilterConfig config) throws ServletException {
            try {
                InputStreamReader certReader = new InputStreamReader(
                        IdpServletCustomResponseTest.class.getResourceAsStream(TEST_CERT_FILENAME));

                PEMReader pemReader = new PEMReader(certReader);
                while (pemReader.ready()) {
                    Object pemObject = pemReader.readObject();
                    if (pemObject instanceof X509Certificate) {
                        x509Certificate = (X509Certificate) pemObject;
                        break;
                    } else {
                        throw new RuntimeException("Unknown type of PEM object: " + pemObject);
                    }
                }
                pemReader.close();
            } catch (IOException e) {
                throw new ServletException(e);
            }
        }
    }
}
