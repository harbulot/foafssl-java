/*
New BSD license: http://opensource.org/licenses/bsd-license.php

Copyright (c) 2008-2009 Sun Microsystems, Inc.
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

import net.java.dev.sommer.foafssl.cache.GraphCacheLookup;
import net.java.dev.sommer.foafssl.cache.MemoryGraphCache;
import net.java.dev.sommer.foafssl.principals.WebIdClaim;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;
import org.junit.Before;
import org.junit.Test;

import java.io.InputStreamReader;
import java.net.*;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * @author Bruno Harbulot.
 * @author Henry Story
 */
public class WebIdClaimTest {

    public static final String TEST_GOOD_FOAF_FILENAME = "dummy-foaf.rdf.xml";
    public static final String TEST_GOOD_FOAF_XHTML_FILENAME = "dummy-foaf.xhtml";
    public static final String TEST_GOOD_FOAF_HTML_FILENAME = "dummy-foaf.html";
    public static final String TEST_WRONG_FOAF_FILENAME = "dummy-foaf-wrong.rdf.xml";
    public static final String TEST_CERT_FILENAME = "dummy-foafsslcert.pem";
    public static final String TEST_FOAF_LOCATION = "http://foaf.example.net/bruno";
    public static final URI TEST_WEB_ID_URI = URI.create(TEST_FOAF_LOCATION + "#me");
    public static final URL TEST_FOAF_URL;
    static private HackableStreamHandlerFactory mockStreamHandlerFactory;
    PublicKey pubkey;

    static {
        try {
            TEST_FOAF_URL = new URL(TEST_FOAF_LOCATION);
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }

        /*
        * TODO: Remove this and just use file mime types
         * Creates a mock URLConnection not to make outside connections to
         * de-reference the FOAF file for the tests.
         * This can only be created once per JVM, so this is a little problematic
         */

         try {
             URL.setURLStreamHandlerFactory(mockStreamHandlerFactory = new HackableStreamHandlerFactory());
         } catch (Throwable e) {
             throw new Error("The tests would wrongly succeed",e);
         }

    }


    @Before
    public void setUp() throws Exception {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        GraphCacheLookup.setCache(new MemoryGraphCache());

        InputStreamReader certReader = new InputStreamReader(WebIdClaimTest.class
                .getResourceAsStream(TEST_CERT_FILENAME));

        PEMReader pemReader = new PEMReader(certReader);
        X509Certificate x509Certificate=null;
        while (pemReader.ready()) {
            Object pemObject = pemReader.readObject();
            if (pemObject instanceof X509Certificate) {
                x509Certificate = (X509Certificate) pemObject;
                break;
            } else {
                throw new RuntimeException("Unknown type of PEM object: " + pemObject);
            }
        }
        pubkey = x509Certificate.getPublicKey();
        pemReader.close();
    }


    @Test
    public void testGoodLocalFoafFile() throws Exception {
        mockStreamHandlerFactory.setUp("application/rdf+xml", TEST_GOOD_FOAF_FILENAME);
        WebIdClaim wic = new WebIdClaim(TEST_WEB_ID_URI,pubkey);
        assertTrue(wic.verify());
    }

    @Test
    public void testGoodLocalFoafXhtmlRDFaFile() throws Exception {
        mockStreamHandlerFactory.setUp("text/html", TEST_GOOD_FOAF_XHTML_FILENAME);
        WebIdClaim pr = new WebIdClaim(TEST_WEB_ID_URI,pubkey);
        assertTrue(pr.verify());
    }

    /**
     * Same test as testGoodLocalFoafXhtmlRDFaFile() but with a different mime type
     * @throws Exception
     */
    @Test
    public void testGoodLocalFoafXhtmlRDFaFile2() throws Exception {
        mockStreamHandlerFactory.setUp("application/xhtml+xml", TEST_GOOD_FOAF_XHTML_FILENAME);
        WebIdClaim pr = new WebIdClaim(TEST_WEB_ID_URI,pubkey);
        assertTrue(pr.verify());
    }


    @Test
    public void testGoodLocalFoafHtmlRDFaFile() throws Exception {
        mockStreamHandlerFactory.setUp("text/html", TEST_GOOD_FOAF_HTML_FILENAME);
        WebIdClaim pr = new WebIdClaim(TEST_WEB_ID_URI,pubkey);
        assertTrue(pr.verify());
    }

    @Test
    public void testBadLocalFoafFile() throws Exception {
        mockStreamHandlerFactory.setUp("application/rdf+xml", TEST_WRONG_FOAF_FILENAME);
        WebIdClaim pr = new WebIdClaim(TEST_WEB_ID_URI,pubkey);
        assertFalse(pr.verify());
    }


    @Test
    public void testLocalBblfishFile_old() throws Exception {
        mockStreamHandlerFactory.setUp("text/html", "bblfish-foaf-old.xhtml");
        WebIdClaim pr = new WebIdClaim(TEST_WEB_ID_URI,pubkey);
        assertTrue(pr.verify());
    }

    @Test
    public void testLocalBblfishFile_old_wrong_mime_type() throws Exception {
        mockStreamHandlerFactory.setUp("application/rdf+xml", "bblfish-foaf-old.xhtml");
        WebIdClaim pr = new WebIdClaim(TEST_WEB_ID_URI,pubkey);
        assertFalse(pr.verify());
    }



    @Test
    public void testLocalBblfishFile_old2() throws Exception {
        mockStreamHandlerFactory.setUp("text/html", "bblfish-foaf-old-2.xhtml");
        WebIdClaim pr = new WebIdClaim(TEST_WEB_ID_URI,pubkey);
        assertTrue(pr.verify());
    }

    @Test
    public void testLocalBblfishFile_old3() throws Exception {
        mockStreamHandlerFactory.setUp("text/html", "bblfish-foaf-old-3.xhtml");
        WebIdClaim pr = new WebIdClaim(TEST_WEB_ID_URI,pubkey);
        assertTrue(pr.verify());
    }

    @Test
    public void testLocalBblfishFile_old4() throws Exception {
        mockStreamHandlerFactory.setUp("text/html", "bblfish-foaf-old-4.xhtml");
        WebIdClaim pr = new WebIdClaim(TEST_WEB_ID_URI,pubkey);
        assertTrue(pr.verify());
    }


    @Test
    public void testLocalBblfishLiteralFile_1() throws Exception {
        mockStreamHandlerFactory.setUp("text/html", "bblfish-foaf-literal-1.xhtml");
        WebIdClaim pr = new WebIdClaim(TEST_WEB_ID_URI,pubkey);
        assertTrue(pr.verify());
    }

    @Test
    public void testLocalBblfishLiteralFile_2() throws Exception {
        mockStreamHandlerFactory.setUp("text/html", "bblfish-foaf-literal-2.xhtml");
        WebIdClaim pr = new WebIdClaim(TEST_WEB_ID_URI,pubkey);
        assertTrue(pr.verify());
   }

    @Test
    public void testLocalBblfishLiteralFile_3() throws Exception {
        mockStreamHandlerFactory.setUp("text/html", "bblfish-foaf-literal-3.xhtml");
        WebIdClaim pr = new WebIdClaim(TEST_WEB_ID_URI,pubkey);
        assertTrue(pr.verify());
    }

    @Test
    public void testLocalBblfishLiteralFile_4() throws Exception {
        mockStreamHandlerFactory.setUp("text/html", "bblfish-foaf-literal-4.xhtml");
        WebIdClaim pr = new WebIdClaim(TEST_WEB_ID_URI,pubkey);
        assertTrue(pr.verify());
    }

    @Test
    public void testLocalBblfishLiteralFile_5() throws Exception {
        mockStreamHandlerFactory.setUp("text/html", "bblfish-foaf-literal-5.xhtml");
        WebIdClaim pr = new WebIdClaim(TEST_WEB_ID_URI,pubkey);
        assertTrue(pr.verify());
    }

    @Test
    public void testLocalBblfishLiteralFile_6() throws Exception {
        mockStreamHandlerFactory.setUp("text/html", "bblfish-foaf-literal-wrong.xhtml");
         WebIdClaim pr = new WebIdClaim(TEST_WEB_ID_URI,pubkey);
         assertFalse(pr.verify());
    }


}
