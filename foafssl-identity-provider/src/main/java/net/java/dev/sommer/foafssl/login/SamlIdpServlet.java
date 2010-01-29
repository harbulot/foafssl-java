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

import java.io.IOException;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.logging.Level;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NameNotFoundException;
import javax.naming.NamingException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.java.dev.sommer.foafssl.principals.FoafSslPrincipal;

import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml2.binding.decoding.HTTPRedirectDeflateDecoder;
import org.opensaml.saml2.binding.encoding.HTTPRedirectDeflateEncoder;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Response;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;

import uk.ac.manchester.rcs.bruno.samlredirector.common.SamlAuthnResponseBuilder;

/**
 * @author Bruno Harbulot (Bruno.Harbulot@manchester.ac.uk)
 * 
 */
@SuppressWarnings("serial")
public class SamlIdpServlet extends AbstractIdpServlet {
    static {
        XMLObjectBuilderFactory xmlObjectBuilderFactory = Configuration.getBuilderFactory();
        if (xmlObjectBuilderFactory.getBuilders().isEmpty()) {
            try {
                DefaultBootstrap.bootstrap();
            } catch (ConfigurationException e) {
                throw new RuntimeException(e);
            }
            xmlObjectBuilderFactory = Configuration.getBuilderFactory();
        }
    }

    public final static String SAMLISSUERNAME_JNDI_NAME = "foafsslidp/samlIssuerName";
    public final static String SAMLKEYNAME_JNDI_NAME = "foafsslidp/samlKeyName";

    public final static String ISSUER_NAME_INITPARAM = "issuerName";
    public final static String KEY_NAME_INITPARAM = "keyName";

    protected Credential signingCredential = null;
    protected String issuerName = null;
    protected String keyName = null;

    /**
     * Initialises the servlet: loads the keystore/keys to use to sign the
     * assertions and the issuer name.
     */
    @Override
    public void init() throws ServletException {
        super.init();

        issuerName = getInitParameter(ISSUER_NAME_INITPARAM);
        keyName = getInitParameter(KEY_NAME_INITPARAM);

        try {
            Context initCtx = new InitialContext();
            Context ctx = (Context) initCtx.lookup("java:comp/env");
            try {
                try {
                    String jndiIssuerName = (String) ctx.lookup(SAMLISSUERNAME_JNDI_NAME);
                    if (jndiIssuerName != null) {
                        issuerName = jndiIssuerName;
                    }
                } catch (NameNotFoundException e) {
                    LOG.log(Level.FINE, "JNDI name not found", e);
                }

                try {
                    String jndiKeyName = (String) ctx.lookup(SAMLKEYNAME_JNDI_NAME);
                    if (jndiKeyName != null) {
                        keyName = jndiKeyName;
                    }
                } catch (NameNotFoundException e) {
                    LOG.log(Level.FINE, "JNDI name not found", e);
                }
            } finally {
                if (ctx != null) {
                    ctx.close();
                }
            }
        } catch (NameNotFoundException e) {
            LOG.log(Level.INFO, "Unable to load JNDI context.", e);
        } catch (NamingException e) {
            LOG.log(Level.INFO, "Unable to load JNDI context.", e);
        }

        signingCredential = SecurityHelper.getSimpleCredential(publicKey, privateKey);
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        Collection<? extends FoafSslPrincipal> verifiedWebIDs = null;

        /*
         * Verifies the certificate passed in the request.
         */
        X509Certificate[] certificates = (X509Certificate[]) request
                .getAttribute("javax.servlet.request.X509Certificate");
        if (certificates != null) {
            X509Certificate foafSslCertificate = certificates[0];
            try {
                verifiedWebIDs = FOAF_SSL_VERIFIER.verifyFoafSslCertificate(foafSslCertificate);
            } catch (Exception e) {
                throw new RuntimeException("Certificate verification failed.");
            }
        }

        if ((verifiedWebIDs != null) && (verifiedWebIDs.size() > 0)) {
            String samlRequestParam = request.getParameter("SAMLRequest");

            if ((samlRequestParam != null) && (samlRequestParam.length() > 0)) {
                /*
                 * Reads the SAML request and generates the SAML response.
                 */
                BasicSAMLMessageContext<AuthnRequest, Response, SAMLObject> msgContext = new BasicSAMLMessageContext<AuthnRequest, Response, SAMLObject>();
                msgContext.setInboundMessageTransport(new HttpServletRequestAdapter(request));

                HTTPRedirectDeflateDecoder decoder = new HTTPRedirectDeflateDecoder();

                try {
                    decoder.decode(msgContext);
                    AuthnRequest authnRequest = msgContext.getInboundSAMLMessage();
                    final String consumerServiceUrl = authnRequest.getAssertionConsumerServiceURL();

                    URI webId = verifiedWebIDs.iterator().next().getUri();

                    Credential signingCredential = null;
                    String issuerName = null;
                    String keyname = null;
                    synchronized (this) {
                        signingCredential = this.signingCredential;
                        issuerName = this.issuerName;
                        keyname = this.keyName;
                    }
                    Response samlResponse = SamlAuthnResponseBuilder.getInstance()
                            .buildSubjectAuthenticatedAssertion(URI.create(issuerName),
                                    Collections.singletonList(URI.create(consumerServiceUrl)),
                                    webId, null, keyname);

                    msgContext.setOutboundMessageTransport(new HttpServletResponseAdapter(response,
                            false));
                    msgContext.setOutboundSAMLMessage(samlResponse);
                    msgContext.setOutboundSAMLMessageSigningCredential(signingCredential);

                    HTTPRedirectDeflateEncoder httpEncoder = new HTTPRedirectDeflateEncoder() {
                        @SuppressWarnings("unchecked")
                        @Override
                        protected String getEndpointURL(SAMLMessageContext messageContext)
                                throws MessageEncodingException {
                            return consumerServiceUrl;
                        }
                    };
                    httpEncoder.encode(msgContext);
                } catch (MessageDecodingException e) {
                    response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                    throw new RuntimeException("Error when decoding the request.", e);
                } catch (SecurityException e) {
                    response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                    throw new RuntimeException("Error when decoding the request.", e);
                } catch (MessageEncodingException e) {
                    throw new RuntimeException("Error when encoding the response.", e);
                }

            } else {
                response.getWriter().print(verifiedWebIDs.iterator().next().getName());
                return;
            }
        } else {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }
    }
}
