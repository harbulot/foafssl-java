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

import java.net.URI;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Collections;
import java.util.List;

/**
 * This class represents a Principal verified by dereferencing the FOAF file at
 * the given Web ID URI.
 * 
 * @author Bruno Harbulot
 */
public class DereferencedFoafSslPrincipal extends WebIdPrincipal {

    protected final boolean deferencedSecurely;
    protected final List<Certificate> foafServerCertificateChain;
    protected final PublicKey publicKey;

    /**
     * Builds FOAF+SSL Principal (considered non-secure dereferencing by
     * default).
     * 
     * @param uri
     *            Web ID.
     */
    public DereferencedFoafSslPrincipal(URI uri) {
        this(uri, null, false);
    }

    /**
     * Builds FOAF+SSL Principal (considered non-secure dereferencing by
     * default).
     * 
     * @param uri
     *            Web ID.
     * @param publicKey
     *            public key used to verify this Web ID.
     */
    public DereferencedFoafSslPrincipal(URI uri, PublicKey publicKey) {
        this(uri, publicKey, false);
    }

    /**
     * Builds FOAF+SSL Principal.
     * 
     * @param uri
     *            Web ID.
     * @param publicKey
     *            public key used to verify this Web ID.
     * @param dereferencedSecurely
     *            true if dereferenced securely (via HTTPS).
     */
    public DereferencedFoafSslPrincipal(URI uri, PublicKey publicKey, boolean dereferencedSecurely) {
        this(uri, publicKey, dereferencedSecurely, null);
    }

    /**
     * Builds FOAF+SSL Principal.
     * 
     * @param uri
     *            Web ID.
     * @param publicKey
     *            public key used to verify this Web ID.
     * @param dereferencedSecurely
     *            true if dereferenced securely (via HTTPS).
     * @param foafServerCertificateChain
     *            certificate chain of the server hosting the dereferenced FOAF
     *            file.
     */
    public DereferencedFoafSslPrincipal(URI uri, PublicKey publicKey, boolean dereferencedSecurely,
            List<Certificate> foafServerCertificateChain) {
        super(uri);
        this.publicKey = publicKey;
        this.deferencedSecurely = dereferencedSecurely;
        if (foafServerCertificateChain != null) {
            this.foafServerCertificateChain = Collections
                    .unmodifiableList(foafServerCertificateChain);
        } else {
            this.foafServerCertificateChain = null;
        }
    }

    /**
     * Returns true if the FOAF file used to verify the Web ID has been
     * dereferenced securely.
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
     *         file, if available. This is a copy of the array held internally.
     */
    public List<Certificate> getFoafServerCertificateChain() {
        return this.foafServerCertificateChain;
    }
}
