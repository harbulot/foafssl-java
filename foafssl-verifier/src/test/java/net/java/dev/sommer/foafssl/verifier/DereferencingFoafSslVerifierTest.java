/*
New BSD license: http://opensource.org/licenses/bsd-license.php

Copyright (c) 2008 Sun Microsystems, Inc.
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
package net.java.dev.sommer.foafssl.verifier;

import static org.junit.Assert.*;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.security.Security;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;
import org.junit.Before;
import org.junit.Test;

/**
 * @author Bruno Harbulot.
 */
public class DereferencingFoafSslVerifierTest {
    public static final URI BRUNO_FOAF_URI = URI
	    .create("http://www.harbulot.com/foaf/bruno#me");
    public static final URI BRUNO_FOAF_DOC_URI = URI
	    .create("http://www.harbulot.com/foaf/bruno");

    public static final String TEST_BRUNO_FOAF_FILENAME = "bruno.rdf.xml";
    public static final String TEST_BRUNO_WRONG_FOAF_FILENAME = "bruno-wrong.rdf.xml";
    public static final String TEST_BRUNO_CERT_FILENAME = "bruno-foafssl.pem";

    private DereferencingFoafSslVerifier verifier;
    private X509Certificate x509Certificate;

    @Before
    public void setUp() throws Exception {
	Security.addProvider(new BouncyCastleProvider());
	this.verifier = new DereferencingFoafSslVerifier();

	InputStreamReader certReader = new InputStreamReader(
		DereferencingFoafSslVerifierTest.class
			.getResourceAsStream(TEST_BRUNO_CERT_FILENAME));

	PEMReader pemReader = new PEMReader(certReader);
	while (pemReader.ready()) {
	    Object pemObject = pemReader.readObject();
	    if (pemObject instanceof X509Certificate) {
		x509Certificate = (X509Certificate) pemObject;
		break;
	    } else {
		throw new RuntimeException("Unknown type of PEM object: "
			+ pemObject);
	    }
	}
	pemReader.close();
    }

    @Test
    public void testGoodLocalFoafFile() throws Exception {

	InputStream foafInputStream = DereferencingFoafSslVerifierTest.class
		.getResourceAsStream(TEST_BRUNO_FOAF_FILENAME);

	try {
	    assertNotNull(this.verifier.verifyByDereferencing(BRUNO_FOAF_URI,
		    this.x509Certificate.getPublicKey(), BRUNO_FOAF_DOC_URI
			    .toURL(), foafInputStream, "application/rdf+xml"));
	} finally {
	    foafInputStream.close();
	}
    }

    @Test
    public void testBadLocalFoafFile() throws Exception {
	InputStream foafInputStream = DereferencingFoafSslVerifierTest.class
		.getResourceAsStream(TEST_BRUNO_WRONG_FOAF_FILENAME);
	try {
	    assertNull(this.verifier.verifyByDereferencing(BRUNO_FOAF_URI,
		    this.x509Certificate.getPublicKey(), BRUNO_FOAF_DOC_URI
			    .toURL(), foafInputStream, "application/rdf+xml"));
	} finally {
	    foafInputStream.close();
	}
    }

    @Test
    public void testRemoteFoafFile() throws Exception {
	assertNotNull(this.verifier.verifyByDereferencing(BRUNO_FOAF_URI,
		this.x509Certificate.getPublicKey()));
    }
}
