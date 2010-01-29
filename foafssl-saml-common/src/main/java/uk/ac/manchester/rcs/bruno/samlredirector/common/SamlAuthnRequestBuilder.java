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
package uk.ac.manchester.rcs.bruno.samlredirector.common;

import java.net.URI;

import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObjectBuilderFactory;

/**
 * This class builds a basic SAML authentication request.
 * 
 * @author Bruno Harbulot (Bruno.Harbulot@manchester.ac.uk)
 */
public class SamlAuthnRequestBuilder {
    public static SamlAuthnRequestBuilder getInstance() {
        return Holder.instance;
    }

    private static class Holder {
        static final SamlAuthnRequestBuilder instance = new SamlAuthnRequestBuilder();
    }

    SAMLObjectBuilder<AuthnRequest> authnRequestBuilder;
    SAMLObjectBuilder<Issuer> issuerBuilder;

    @SuppressWarnings("unchecked")
    private SamlAuthnRequestBuilder() {
        XMLObjectBuilderFactory xmlObjectBuilderFactory = Configuration.getBuilderFactory();
        if (xmlObjectBuilderFactory.getBuilders().isEmpty()) {
            try {
                DefaultBootstrap.bootstrap();
            } catch (ConfigurationException e) {
                throw new RuntimeException(e);
            }
            xmlObjectBuilderFactory = Configuration.getBuilderFactory();
        }

        authnRequestBuilder = (SAMLObjectBuilder<AuthnRequest>) xmlObjectBuilderFactory
                .getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);
        issuerBuilder = (SAMLObjectBuilder<Issuer>) xmlObjectBuilderFactory
                .getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
    }

    public AuthnRequest buildAuthnRequest(URI consumerServiceUri) {
        AuthnRequest authnRequest = authnRequestBuilder.buildObject();
        authnRequest.setAssertionConsumerServiceURL(consumerServiceUri.toASCIIString());
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(consumerServiceUri.toASCIIString());
        authnRequest.setIssuer(issuer);
        return authnRequest;
    }
}
