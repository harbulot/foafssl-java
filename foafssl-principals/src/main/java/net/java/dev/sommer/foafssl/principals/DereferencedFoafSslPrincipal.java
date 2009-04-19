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
import java.security.cert.Certificate;

/**
 * This class represents a Principal verified by dereferencing the FOAF file at
 * the given Web ID URI.
 * 
 * @author Bruno Harbulot
 */
public class DereferencedFoafSslPrincipal extends FoafSslPrincipal {

    protected final boolean deferencedSecurely;
    protected final Certificate[] foafServerCertificateChain;

    /**
     * Builds FOAF+SSL Principal (considered non-secure dereferencing by
     * default).
     * 
     * @param uri
     *            Web ID.
     */
    public DereferencedFoafSslPrincipal(URI uri) {
        this(uri, false);
    }

    /**
     * Builds FOAF+SSL Principal.
     * 
     * @param uri
     *            Web ID.
     * @param dereferencedSecurely
     *            true if dereferenced securely (via HTTPS).
     */
    public DereferencedFoafSslPrincipal(URI uri, boolean dereferencedSecurely) {
        this(uri, dereferencedSecurely, null);
    }

    /**
     * Builds FOAF+SSL Principal.
     * 
     * @param uri
     *            Web ID.
     * @param dereferencedSecurely
     *            true if dereferenced securely (via HTTPS).
     * @param foafServerCertificateChain
     *            certificate chain of the server hosting the dereferenced FOAF
     *            file.
     */
    public DereferencedFoafSslPrincipal(URI uri, boolean dereferencedSecurely,
            Certificate[] foafServerCertificateChain) {
        super(uri);
        this.deferencedSecurely = dereferencedSecurely;
        if (foafServerCertificateChain != null) {
            this.foafServerCertificateChain = new Certificate[foafServerCertificateChain.length];
            for (int i = 0; i < foafServerCertificateChain.length; i++) {
                this.foafServerCertificateChain[i] = foafServerCertificateChain[i];
            }
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
    public Certificate[] getFoafServerCertificateChain() {
        if (this.foafServerCertificateChain != null) {
            Certificate[] certs = new Certificate[this.foafServerCertificateChain.length];
            for (int i = 0; i < certs.length; i++) {
                certs[i] = this.foafServerCertificateChain[i];
            }
            return certs;
        } else {
            return null;
        }
    }
}
