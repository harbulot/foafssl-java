/*
New BSD license: http://opensource.org/licenses/bsd-license.php

Copyright (c) 2009 Sun Microsystems, Inc.
901 San Antonio Road, Palo Alto, CA 94303 USA. 
All rights reserved.


Redistribution and use in source and binary forms, with or without 
modification, are permitted provided that the following conditions are met:

- Redistributions of source code must retain the above copyright notice, 
this list of conditions and the following disclaimer.
- Redistributions in binary form must reproduce the above copyright notice, 
this list of conditions and the following disclaimer in the documentation 
and/or other materials provided with the distribution.
- Neither the name of Sun Microsystems, Inc. nor the names of its contributors
may be used to endorse or promote products derived from this software 
without specific prior written permission.

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
 */
package net.java.dev.sommer.foafssl.principals;

import net.java.dev.sommer.foafssl.cache.GraphCache;
import net.java.dev.sommer.foafssl.cache.GraphCacheLookup;
import net.java.dev.sommer.foafssl.verifier.FoafSslVerifier;
import net.java.dev.sommer.foafssl.verifier.SesameFoafSslVerifier;
import org.openrdf.OpenRDFException;
import org.openrdf.model.Literal;
import org.openrdf.model.Resource;
import org.openrdf.model.Value;
import org.openrdf.model.ValueFactory;
import org.openrdf.query.*;
import org.openrdf.repository.sail.SailRepositoryConnection;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import java.util.logging.Logger;

/**
 * This is an abstract class for a FOAF+SSL principal.
 * http://en.wikipedia.org/wiki/Security_principal
 * <p/>
 * todo: Perhaps one could have a WebIdClaim be composed of specialised princpals,
 * todo: each for an alternative  name in the certificate.
 *
 * @author Bruno Harbulot
 */
public class WebIdClaim implements Principal {
 
    /**
     * FOAF+SSL URI, a.k.a Web ID.
     */
    protected final URI webid;
    protected final PublicKey pubKey;

    protected boolean deferencedSecurely;
    protected List<Certificate> foafServerCertificateChain;


    /**
     * Creates a FOAF+SSL X509Claim.
     * Principals are uniquely identified by a URI, The URI refers to them.
     *
     * @param webid Web ID.
     * @pram cert the cert in which the web id was found and for which one knows the client has a private key
     */
    public WebIdClaim(URI webid, PublicKey key) {
        this.webid = webid;
        this.pubKey = key;
    }

    /**
     * Returns the Web ID.
     *
     * @return the Web ID.
     */
    public URI getWebid() {
        return this.webid;
    }

    /**
     * currently Returns the Web ID,
     * todo: perhaps it would be better to return a first last name pair
     *
     * @return the Web ID.
     */
    public String getName() {
        return getWebid().toASCIIString();
    }

    /**
     * Returns the WebId as an ASCII string
     */
    public String toString() {
        return webid.toASCIIString();
    }

    /**
     * Verifies a claimed Web ID and its public key against the public key
     * available by dereferencing this Web ID.
     */
    public boolean verify() {
        return FoafSslVerifier.getVerifier().verify(this);
    }


    /**
     * Returns true if the FOAF file used to verify the Web ID has been
     * dereferenced securely.
     * <p/>
     * A similar function could return a number for different levels of authentication
     * Or it could return a reasoning to explain what graphs it relied on, so that
     * if in the future any of those were put into question this could change....
     *
     * @return true if the FOAF file used to verify the Web ID has been
     *         dereferenced securely
     */
    public boolean isDeferencedSecurely() {
        return this.deferencedSecurely;
    }

    /**
     * Returns the certificate chain of the server hosting the dereferenced FOAF
     * file, if available. This could be used to be more choosy on which hosting
     * servers to trust.
     *
     * @return certificate chain of the server hosting the dereferenced FOAF
     *         file, if available. The list is unchangeable.
     */
    public List<Certificate> getServerCertificateChain() {
        return foafServerCertificateChain;
    }

    /**
     * If the server from which the WebId when dereferenced serves a representation, has a certificate cjaom then this is
     * saved here
     *
     * @param serverCertificateChain
     */
    public void setServerCertificateChain(Certificate[] serverCertificateChain) {
        if (foafServerCertificateChain != null) {
            ArrayList<Certificate> certs = new ArrayList<Certificate>(serverCertificateChain.length);
            certs.addAll(Arrays.asList(serverCertificateChain));
            this.foafServerCertificateChain = Collections.unmodifiableList(certs);
        }
    }


    LinkedList<Throwable> problemDescription = new LinkedList<Throwable>();

    /**
     * Describe the problem that was come accross
     * (this perhaps should be addProblem, in case on can have a nbr of problems)
     *
     * @param description
     */
    public void addProblem(Throwable description) {
        this.problemDescription.add(description);
    }

    public LinkedList<Throwable> getProblems() {
        return problemDescription;
    }

    boolean verified = false;

    public void fail(String reason) {
        addProblem(new Error(reason));
    }

    public boolean verified() {
        return verified;
    }

    public void fail(String message, Exception e) {
        addProblem(new Error(message, e));
    }

    public void warn(String message) {
        addProblem(new Warning(message));
    }

    public PublicKey getVerifiedPublicKey() {
        return pubKey;
    }


}


