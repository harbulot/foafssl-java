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
import java.util.List;

import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.Subject;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.KeyName;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;

import uk.ac.manchester.rcs.bruno.samlredirector.common.SamlAuthnResponseBuilder;

/**
 * This class builds a SAML assertion after a URI has been authenticated
 * successfully.
 * 
 * @author Bruno Harbulot (Bruno.Harbulot@manchester.ac.uk)
 * 
 */
public class SamlAuthnResponseBuilder {
    /**
     * @return singleton.
     */
    public static SamlAuthnResponseBuilder getInstance() {
        return Holder.instance;
    }

    /**
     * Singleton holder.
     */
    private static class Holder {
        static final SamlAuthnResponseBuilder instance = new SamlAuthnResponseBuilder();
    }

    SAMLObjectBuilder<Subject> subjectBuilder;
    SAMLObjectBuilder<NameID> nameIdBuilder;
    SAMLObjectBuilder<Assertion> assertionBuilder;
    SAMLObjectBuilder<AuthnStatement> authStatementBuilder;
    SAMLObjectBuilder<Response> responseBuilder;
    SAMLObjectBuilder<Issuer> issuerBuilder;
    SAMLObjectBuilder<Conditions> conditionsBuilder;
    SAMLObjectBuilder<AudienceRestriction> audienceRestrictionBuilder;
    SAMLObjectBuilder<Audience> audienceBuilder;
    SAMLObjectBuilder<Status> statusBuilder;
    SAMLObjectBuilder<StatusCode> statusCodeBuilder;
    XMLObjectBuilder<Signature> signatureBuilder;
    XMLObjectBuilder<KeyName> keynameBuilder;

    /**
     * Constructor. Initialiases the various SAML object builders of OpenSAML.
     */
    @SuppressWarnings("unchecked")
    private SamlAuthnResponseBuilder() {
        XMLObjectBuilderFactory xmlObjectBuilderFactory = Configuration.getBuilderFactory();
        if (xmlObjectBuilderFactory.getBuilders().isEmpty()) {
            try {
                DefaultBootstrap.bootstrap();
            } catch (ConfigurationException e) {
                throw new RuntimeException(e);
            }
            xmlObjectBuilderFactory = Configuration.getBuilderFactory();
        }

        subjectBuilder = (SAMLObjectBuilder<Subject>) xmlObjectBuilderFactory
                .getBuilder(Subject.DEFAULT_ELEMENT_NAME);

        nameIdBuilder = (SAMLObjectBuilder<NameID>) xmlObjectBuilderFactory
                .getBuilder(NameID.DEFAULT_ELEMENT_NAME);

        assertionBuilder = (SAMLObjectBuilder<Assertion>) xmlObjectBuilderFactory
                .getBuilder(Assertion.DEFAULT_ELEMENT_NAME);

        authStatementBuilder = (SAMLObjectBuilder<AuthnStatement>) xmlObjectBuilderFactory
                .getBuilder(AuthnStatement.DEFAULT_ELEMENT_NAME);

        responseBuilder = (SAMLObjectBuilder<Response>) xmlObjectBuilderFactory
                .getBuilder(Response.DEFAULT_ELEMENT_NAME);

        issuerBuilder = (SAMLObjectBuilder<Issuer>) xmlObjectBuilderFactory
                .getBuilder(Issuer.DEFAULT_ELEMENT_NAME);

        conditionsBuilder = (SAMLObjectBuilder<Conditions>) xmlObjectBuilderFactory
                .getBuilder(Conditions.DEFAULT_ELEMENT_NAME);

        audienceRestrictionBuilder = (SAMLObjectBuilder<AudienceRestriction>) xmlObjectBuilderFactory
                .getBuilder(AudienceRestriction.DEFAULT_ELEMENT_NAME);

        audienceBuilder = (SAMLObjectBuilder<Audience>) xmlObjectBuilderFactory
                .getBuilder(Audience.DEFAULT_ELEMENT_NAME);

        statusBuilder = (SAMLObjectBuilder<Status>) xmlObjectBuilderFactory
                .getBuilder(Status.DEFAULT_ELEMENT_NAME);

        statusCodeBuilder = (SAMLObjectBuilder<StatusCode>) xmlObjectBuilderFactory
                .getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);

        signatureBuilder = (XMLObjectBuilder<Signature>) xmlObjectBuilderFactory
                .getBuilder(Signature.DEFAULT_ELEMENT_NAME);

        keynameBuilder = (XMLObjectBuilder<KeyName>) xmlObjectBuilderFactory
                .getBuilder(KeyName.DEFAULT_ELEMENT_NAME);
    }

    public Response buildSubjectAuthenticatedAssertion(URI issuerId, List<URI> consumerIds,
            URI subjectId, Credential signingCredential) {
        return buildSubjectAuthenticatedAssertion(issuerId, consumerIds, subjectId,
                signingCredential, null, new DateTime());
    }

    public Response buildSubjectAuthenticatedAssertion(URI issuerId, List<URI> consumerIds,
            URI subjectId, Credential signingCredential, String keyNameValue) {
        return buildSubjectAuthenticatedAssertion(issuerId, consumerIds, subjectId,
                signingCredential, keyNameValue, new DateTime());
    }

    public Response buildSubjectAuthenticatedAssertion(URI issuerId, List<URI> consumerIds,
            URI subjectId, Credential signingCredential, DateTime dateTime) {
        return buildSubjectAuthenticatedAssertion(issuerId, consumerIds, subjectId,
                signingCredential, null, dateTime);
    }

    public Response buildSubjectAuthenticatedAssertion(URI issuerId, List<URI> consumerIds,
            URI subjectId, Credential signingCredential, String keyNameValue, DateTime dateTime) {
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(issuerId.toASCIIString());

        NameID nameId = nameIdBuilder.buildObject();
        // TODO nameId.setFormat("http://foafssl.org/foafsslid");
        nameId.setValue(subjectId.toASCIIString());

        Subject subject = subjectBuilder.buildObject();
        subject.setNameID(nameId);

        AuthnStatement authnStatement = authStatementBuilder.buildObject();
        authnStatement.setAuthnInstant(dateTime);

        Assertion assertion = assertionBuilder.buildObject();
        assertion.setSubject(subject);
        if ((consumerIds != null) && (consumerIds.size() > 0)) {
            Conditions conditions = conditionsBuilder.buildObject();
            AudienceRestriction audienceRestriction = audienceRestrictionBuilder.buildObject();
            for (URI consumerId : consumerIds) {
                Audience audience = audienceBuilder.buildObject();
                audience.setAudienceURI(consumerId.toASCIIString());
                audienceRestriction.getAudiences().add(audience);
            }
            conditions.getAudienceRestrictions().add(audienceRestriction);
            assertion.setConditions(conditions);
        }
        assertion.getAuthnStatements().add(authnStatement);
        assertion.setIssuer(issuer);

        org.opensaml.saml2.core.Response response = responseBuilder.buildObject();
        response.getAssertions().add(assertion);

        StatusCode statusCode = statusCodeBuilder.buildObject();
        statusCode.setValue(StatusCode.SUCCESS_URI);
        Status status = statusBuilder.buildObject();
        status.setStatusCode(statusCode);
        response.setStatus(status);

        if (signingCredential != null) {
            try {
                Signature signature = signatureBuilder.buildObject(Signature.DEFAULT_ELEMENT_NAME);
                SecurityHelper.prepareSignatureParams(signature, signingCredential, null, null);
                signature.getKeyInfo().getKeyValues().clear();
                if (keyNameValue != null) {
                    KeyName keyname = keynameBuilder.buildObject(KeyName.DEFAULT_ELEMENT_NAME);
                    keyname.setValue(keyNameValue);
                    signature.getKeyInfo().getKeyNames().add(keyname);
                }

                signature.setSigningCredential(signingCredential);
                response.setSignature(signature);

                Configuration.getMarshallerFactory().getMarshaller(response).marshall(response);
                Signer.signObject(signature);
            } catch (SecurityException e) {
                throw new RuntimeException(e);
            } catch (MarshallingException e) {
                throw new RuntimeException(e);
            } catch (SignatureException e) {
                throw new RuntimeException(e);
            }
        }

        return response;
    }
}
