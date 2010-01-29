/**-----------------------------------------------------------------------
  
Copyright (c) 2009-2010, The University of Manchester, United Kingdom.
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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.net.URLStreamHandler;
import java.net.URLStreamHandlerFactory;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
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
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;
import org.joda.time.DateTime;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mortbay.jetty.servlet.ServletHolder;
import org.mortbay.jetty.testing.HttpTester;
import org.mortbay.jetty.testing.ServletTester;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml2.binding.decoding.HTTPRedirectDeflateDecoder;
import org.opensaml.saml2.binding.encoding.HTTPRedirectDeflateEncoder;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.metadata.AuthnQueryService;
import org.opensaml.saml2.metadata.impl.AuthnQueryServiceImpl;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.util.Base64;
import org.restlet.data.Form;
import org.restlet.data.Method;
import org.restlet.data.Reference;
import org.restlet.data.Request;
import org.w3c.dom.Element;

import uk.ac.manchester.rcs.bruno.samlredirector.common.SamlAuthnRequestBuilder;
import uk.ac.manchester.rcs.bruno.samlredirector.misc.RestletRequestInTransportAdapter;
import uk.ac.manchester.rcs.bruno.samlredirector.misc.RestletResponseOutTransportAdapter;

/**
 * @author Bruno Harbulot (Bruno.Harbulot@manchester.ac.uk)
 */
public class SamlIdpServletTest {
    public final static String CERTIFICATES_DIRECTORY = "org/jsslutils/certificates/";
    public final static String KEYSTORE_PASSWORD_STRING = "testtest";
    public final static char[] KEYSTORE_PASSWORD = KEYSTORE_PASSWORD_STRING.toCharArray();

    private static final String TEST_IDP_KEYNAME = "http://idp.example.org/idp/#pubkey";
    private static final String TEST_IDP_URI = "http://idp.example.org/idp/";
    private static final String TEST_SP_URI = "http://sp.example.com/sp/";

    public static final String TEST_BRUNO_FOAF_FILENAME = "dummy-foaf.rdf.xml";
    public static final String TEST_BRUNO_CERT_FILENAME = "dummy-foafsslcert.pem";
    public static final String TEST_BRUNO_FOAF_ID = "http://foaf.example.net/bruno#me";

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
                ctx = (Context) ctx.lookup("foafsslidp");
            } catch (NameNotFoundException e) {
                ctx = ctx.createSubcontext("foafsslidp");
            }
            ctx.rebind("signingKeyStore", getKeyStore());
            ctx.rebind("signingKeyPasswordArray", KEYSTORE_PASSWORD);
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
            @Override
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
                                    return SamlIdpServletTest.class
                                            .getResourceAsStream(TEST_BRUNO_FOAF_FILENAME);
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
        ServletHolder servletHolder = idpServletTester.addServlet(SamlIdpServlet.class, "/*");
        servletHolder.setInitParameter("issuerName", TEST_IDP_URI);
        servletHolder.setInitParameter("keyName", TEST_IDP_KEYNAME);
        idpServletTester.start();
    }

    @Test
    public void testRequest() throws Exception {
        /*
         * Creates a SAML message context for the fake authn request.
         */
        BasicSAMLMessageContext<SAMLObject, AuthnRequest, SAMLObject> fakeAuthnReqOutMsgContext = new BasicSAMLMessageContext<SAMLObject, AuthnRequest, SAMLObject>();

        /*
         * TheSAML authn request is sent via anHTTP response which is a
         * redirection and will thus trigger a newHTTP request to the URL in the
         * Location header.
         * 
         * Using a Restlet Response object to fake the serialisation makes it a
         * bit easier to parse that redirection. There is no actual Restlet
         * connection involved here.
         */
        org.restlet.data.Response fakeHttpResponse = new org.restlet.data.Response(new Request());
        RestletResponseOutTransportAdapter fakeAuthnReqOutTransport = new RestletResponseOutTransportAdapter(
                fakeHttpResponse);
        AuthnRequest authnRequest = SamlAuthnRequestBuilder.getInstance().buildAuthnRequest(
                URI.create(TEST_SP_URI));
        assertNotNull(authnRequest);
        assertEquals(TEST_SP_URI, authnRequest.getIssuer().getValue());
        fakeAuthnReqOutMsgContext.setOutboundSAMLMessage(authnRequest);
        fakeAuthnReqOutMsgContext.setOutboundMessageTransport(fakeAuthnReqOutTransport);
        fakeAuthnReqOutMsgContext.setPeerEntityEndpoint(new AuthnQueryServiceImpl(
                AuthnQueryService.DEFAULT_ELEMENT_NAME.getNamespaceURI(),
                AuthnQueryService.DEFAULT_ELEMENT_NAME.getLocalPart(),
                AuthnQueryService.DEFAULT_ELEMENT_NAME.getPrefix()) {
            @Override
            public String getLocation() {
                return TEST_IDP_URI;
            }
        });

        /*
         * Encodes the SAML request with the Deflate encoder, which will put the
         * encoded value in the Location header of the fakeHttpResponse passed
         * in the fakeAuthnReqOutMsgContext.
         */
        HTTPRedirectDeflateEncoder httpEncoder = new HTTPRedirectDeflateEncoder();
        httpEncoder.encode(fakeAuthnReqOutMsgContext);

        /*
         * Sets up the request in the Jetty tester. The URL to which to send the
         * SAML authn request is in the Location header of the fakeHttpResponse.
         */
        HttpTester request = new HttpTester();
        HttpTester response = new HttpTester();
        Reference resourceRef = fakeHttpResponse.getLocationRef();
        request.setHeader("Host", resourceRef.getHostDomain());
        request.setMethod("GET");
        String authReqUrlQueryPart = resourceRef.getQuery();
        request.setURI(resourceRef.getPath()
                + (authReqUrlQueryPart != null ? "?" + authReqUrlQueryPart : ""));

        /*
         * Fakes the presence of a client certificate.
         */
        idpServletTester.addFilter(FakeClientCertInsertionFilter.class, "/*", 0);

        /*
         * Performs the request.
         */
        response.parse(idpServletTester.getResponses(request.generate()));

        System.out.println();
        System.out.println("Response status: " + response.getStatus());
        String location = response.getHeader("Location");
        System.out.println("Response Location header: " + location);
        System.out.println("Response Location header length: " + location.length());
        System.out.println();

        /*
         * Creates a SAML message context to process the response.
         */
        BasicSAMLMessageContext<Response, SAMLObject, SAMLObject> authnResponseInMsgContext = new BasicSAMLMessageContext<Response, SAMLObject, SAMLObject>();
        Request restletRequest = new Request();
        restletRequest.setResourceRef(location);
        restletRequest.setMethod(Method.GET);

        /*
         * Tries to verify the signature, if present.
         */
        Form samlResponseUrlQueryPart = restletRequest.getResourceRef().getQueryAsForm();
        String signatureParam = samlResponseUrlQueryPart.getFirstValue("Signature");

        assertNotNull("Signature?", signatureParam);

        if (signatureParam != null) {
            String samlResponseParam = samlResponseUrlQueryPart.getFirstValue("SAMLResponse");
            String relayStateParam = samlResponseUrlQueryPart.getFirstValue("RelayState");
            String sigAlgParam = samlResponseUrlQueryPart.getFirstValue("SigAlg");
            String signedMessage = "SAMLResponse=" + URLEncoder.encode(samlResponseParam, "UTF-8");
            if (relayStateParam != null) {
                signedMessage += "&RelayState=" + URLEncoder.encode(relayStateParam, "UTF-8");
            }
            signedMessage += "&SigAlg=" + URLEncoder.encode(sigAlgParam, "UTF-8");

            byte[] signatureBytes = Base64.decode(signatureParam);
            String sigAlg = null;
            if (SignatureMethod.DSA_SHA1.equals(sigAlgParam)) {
                sigAlg = "SHA1withDSA";
            } else if (SignatureMethod.RSA_SHA1.equals(sigAlgParam)) {
                sigAlg = "SHA1withRSA";
            } else {
                fail("Unsupported signature algorithm.");
            }
            Signature signature = Signature.getInstance(sigAlg);
            signature.initVerify(getPublicKey());
            signature.update(signedMessage.getBytes());
            assertTrue("Signature verified?", signature.verify(signatureBytes));
        }

        /*
         * Uses a dumy Restlet-based transport for ease of request processing.
         */
        RestletRequestInTransportAdapter inTransport = new RestletRequestInTransportAdapter(
                restletRequest);
        authnResponseInMsgContext.setInboundMessageTransport(inTransport);

        HTTPRedirectDeflateDecoder decoder = new HTTPRedirectDeflateDecoder() {
            @SuppressWarnings("unchecked")
            @Override
            protected void checkEndpointURI(SAMLMessageContext messageContext)
                    throws SecurityException, MessageDecodingException {
                // boolean destRequired =
                // isIntendedDestinationEndpointURIRequired(messageContext);
                // System.err.println("Binding requires destination endpoint? "
                // + destRequired);
                // System.err.println("Destination Endpoint: "
                // + getIntendedDestinationEndpointURI(messageContext));
            }
        };
        decoder.decode(authnResponseInMsgContext);

        Response samlResponse = authnResponseInMsgContext.getInboundSAMLMessage();
        assertNotNull(samlResponse);

        /*
         * Tests the response.
         */
        assertNotNull(samlResponse.getAssertions());
        assertEquals(1, samlResponse.getAssertions().size());
        Assertion samlAssertion = samlResponse.getAssertions().get(0);
        assertNotNull(samlAssertion);

        /*
         * Marshal the response for display.
         */
        MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
        Marshaller marshaller = marshallerFactory.getMarshaller(samlResponse);
        Element responseElement = marshaller.marshall(samlResponse);

        /*
         * Displays the XML result.
         */
        System.out.println();
        TransformerFactory tFactory = TransformerFactory.newInstance();
        Transformer t = tFactory.newTransformer();
        Source xmlSource = new DOMSource(responseElement);
        StreamResult streamResult = new StreamResult(System.out);
        t.transform(xmlSource, streamResult);
        System.out.println();
        System.out.println();

        /*
         * Carry on testing the assertion.
         */
        assertNotNull(samlAssertion.getSubject());
        assertNotNull(samlAssertion.getSubject().getNameID());
        // assertEquals("... some format ...", responseAssertion.getSubject()
        // .getNameID().getFormat());
        assertEquals(TEST_BRUNO_FOAF_ID, samlAssertion.getSubject().getNameID().getValue());
        assertNotNull(samlAssertion.getAuthnStatements());
        assertEquals(1, samlAssertion.getAuthnStatements().size());
        AuthnStatement samlAuthnStatement = samlAssertion.getAuthnStatements().get(0);
        DateTime authnTime = samlAuthnStatement.getAuthnInstant();
        assertTrue("Time correct (1)? ", authnTime.isBeforeNow());
        assertTrue("Time correct (2)? ", authnTime.isAfter(authnTime.minusMillis(100).getMillis()));
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

        @Override
        public void destroy() {
        }

        @Override
        public void doFilter(ServletRequest request, ServletResponse response, FilterChain next)
                throws IOException, ServletException {
            request.setAttribute("javax.servlet.request.X509Certificate",
                    new X509Certificate[] { x509Certificate });
            next.doFilter(request, response);
        }

        @Override
        public void init(FilterConfig config) throws ServletException {
            try {
                InputStreamReader certReader = new InputStreamReader(SamlIdpServletTest.class
                        .getResourceAsStream(TEST_BRUNO_CERT_FILENAME));

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
