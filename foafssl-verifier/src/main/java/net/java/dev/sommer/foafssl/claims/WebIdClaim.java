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
package net.java.dev.sommer.foafssl.claims;

import java.net.URI;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import net.java.dev.sommer.foafssl.principals.DereferencedFoafSslPrincipal;
import net.java.dev.sommer.foafssl.principals.WebIdPrincipal;
import net.java.dev.sommer.foafssl.verifier.FoafSslVerifier;

/**
 * This is an abstract class for a FOAF+SSL WebId claim.
 * 
 * @author Bruno Harbulot
 * @author Henry Story
 */
public class WebIdClaim {
    /**
     * FOAF+SSL URI, a.k.a Web ID.
     */
    private final URI webid;
    private final PublicKey pubKey;

    private boolean deferencedSecurely;
    //bruno says he is not quite sure why volatile is here and not elsewhere
    private volatile List<Certificate> foafServerCertificateChain;

    private boolean verified = false;
    private LinkedList<Throwable> problemDescription = new LinkedList<Throwable>();

    /**
     * Creates a Web ID claim.
     * 
     * @param webid
     *            Web ID.
     * @param key
     *            the public key claimed to be associated with this WebID
     *            (obtained from the certificate).
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
    public URI getWebId() {
        return this.webid;
    }

    /**
     * Returns the Web ID as an ASCII string.
     */
    public String toString() {
        return webid.toASCIIString();
    }

    /**
     * Verifies a claimed Web ID and its public key against the public key
     * available by dereferencing this Web ID.
     */
    public boolean verify() {
        return verify(FoafSslVerifier.getVerifier());
    }

    /**
     * Verifies a claimed Web ID and its public key against the public key
     * available by dereferencing this Web ID.
     */
    public boolean verify(FoafSslVerifier verifier) {
        return verifier.verify(this);
    }

    /**
     * Returns true if the FOAF file used to verify the Web ID has been
     * dereferenced securely.
     * <p>
     * A similar function could return a number for different levels of
     * authentication Or it could return a reasoning to explain what graphs it
     * relied on, so that if in the future any of those were put into question
     * this could change....
     * </p>
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
     * If the server from which the Web ID when dereferenced serves a
     * representation, has a certificate chain then this is saved here
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

    /**
     * Describe the problem that was come accross (this perhaps should be
     * addProblem, in case on can have a nbr of problems)
     * 
     * @param description
     */
    public void addProblem(Throwable description) {
        this.problemDescription.add(description);
    }

    public LinkedList<Throwable> getProblems() {
        return problemDescription;
    }

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

    public WebIdPrincipal getPrincipal() {
        if (verified()) {
            return new DereferencedFoafSslPrincipal(this.webid, this.pubKey,
                    this.deferencedSecurely, this.foafServerCertificateChain);
        } else {
            return null;
        }
    }
}
