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

import java.io.InputStream;
import java.net.URLConnection;
import java.security.PublicKey;
import java.util.logging.Logger;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URISyntaxException;
import java.net.URI;
import java.net.URL;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Iterator;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

import javax.net.ssl.HttpsURLConnection;

import net.java.dev.sommer.foafssl.principals.DereferencedFoafSslPrincipal;
import net.java.dev.sommer.foafssl.principals.FoafSslPrincipal;

import org.openrdf.OpenRDFException;
import org.openrdf.model.ValueFactory;
import org.openrdf.query.Binding;
import org.openrdf.query.BindingSet;
import org.openrdf.query.QueryLanguage;
import org.openrdf.query.TupleQuery;
import org.openrdf.query.TupleQueryResult;
import org.openrdf.repository.RepositoryConnection;
import org.openrdf.repository.sail.SailRepository;
import org.openrdf.rio.RDFFormat;
import org.openrdf.sail.memory.MemoryStore;

/**
 * @author Henry Story.
 * @author Bruno Harbulot.
 */
public class DereferencingFoafSslVerifier implements FoafSslVerifier {

	static transient Logger log = Logger.getLogger(DereferencingFoafSslVerifier.class.getName());

	public Collection<? extends FoafSslPrincipal> verifyFoafSslCertificate(
			  X509Certificate clientCert) throws OpenRDFException, IOException {
		List<DereferencedFoafSslPrincipal> verifiedUris = new ArrayList<DereferencedFoafSslPrincipal>();
		List<URI> candidateUris = getAlternativeURIName(clientCert);

		for (URI candidateUri : candidateUris) {
			DereferencedFoafSslPrincipal principal = verifyByDereferencing(
					  candidateUri, clientCert.getPublicKey());
			if (principal != null) {
				verifiedUris.add(principal);
			}
		}
		return verifiedUris;
	}

	public DereferencedFoafSslPrincipal verifyByDereferencing(URI claimedIdUri,
			  PublicKey certPublicKey) throws OpenRDFException, IOException {
		URL foafname = claimedIdUri.toURL();
		URLConnection conn = foafname.openConnection();

		conn.addRequestProperty("Accept:", "application/rdf+xml");
		conn.connect();

		InputStream is = conn.getInputStream();
		try {
			boolean dereferencedSecurely = false;
			Certificate[] foafServerCertificates = null;
			if (conn instanceof HttpsURLConnection) {
				dereferencedSecurely = true;
				foafServerCertificates = ((HttpsURLConnection) conn).getServerCertificates();
			}
			String mimeType = mimeType(conn.getContentType());
			return verifyByDereferencing(claimedIdUri, certPublicKey, conn.getURL(), is, mimeType, dereferencedSecurely,
					  foafServerCertificates);
		} finally {
			is.close();
		}
	}

	public DereferencedFoafSslPrincipal verifyByDereferencing(URI claimedIdUri,
			  PublicKey certPublicKey, URL actualUrl,
			  InputStream foafDocInputStream, String foafMediaType)
			  throws OpenRDFException, IOException {
		return verifyByDereferencing(claimedIdUri, certPublicKey, actualUrl,
				  foafDocInputStream, foafMediaType, false, null);
	}

	public DereferencedFoafSslPrincipal verifyByDereferencing(URI claimedIdUri,
			  PublicKey certPublicKey, URL actualUrl,
			  InputStream foafDocInputStream, String foafMediaType,
			  boolean dereferencedSecurely, Certificate[] foafServerCertificates)
			  throws OpenRDFException, IOException {
		RDFFormat rdfFormat = RDFFormat.forMIMEType(foafMediaType);

		URL base = new URL(actualUrl.getProtocol(), actualUrl.getHost(),
				  actualUrl.getPort(), actualUrl.getFile()); // all of this needs

		MemoryStore mem = new MemoryStore();
		mem.initialize();
		SailRepository sail = new SailRepository(mem);
		RepositoryConnection rep = sail.getConnection();
		ValueFactory vf = sail.getValueFactory();

		// to be better
		org.openrdf.model.URI foafdocUri = vf.createURI(base.toString());
		rep.add(foafDocInputStream, actualUrl.toString(), rdfFormat,
				  foafdocUri);
		if (certPublicKey instanceof RSAPublicKey) {
			RSAPublicKey certRsakey = (RSAPublicKey) certPublicKey;
			TupleQuery query = rep.prepareTupleQuery(
					  QueryLanguage.SPARQL,
					  "PREFIX cert: <http://www.w3.org/ns/auth/cert#>" +
					  "PREFIX rsa: <http://www.w3.org/ns/auth/rsa#>" +
					  "SELECT ?mod ?exp " + "WHERE {" +
					  "   ?sig cert:identity ?person ." +
					  "   ?sig a rsa:RSAPublicKey;" +
					  "        rsa:modulus [ cert:hex ?mod ] ;" +
					  "        rsa:public_exponent [ cert:decimal ?exp ] ." +
					  "}");
			// TODO: allow optional different ways of encoding the
			// modulus and exponent integers
			// this would just require passing the relations and the
			// value to a function.
			query.setBinding("person", vf.createURI(claimedIdUri.toString()));
			TupleQueryResult answer = query.evaluate();
			while (answer.hasNext()) {
				BindingSet binding = answer.next();
				Binding value = binding.getBinding("mod");
				if (value != null) {
					// check that the value and type match the one
					// on the signature
					String strval = cleanHex(value.getValue().stringValue());
					BigInteger foaf_modulus = new BigInteger(strval, 16);
					if (!foaf_modulus.equals(certRsakey.getModulus())) {
						continue;
					}
				} else {
					continue;
				}

				value = binding.getBinding("exp");
				if (value != null) {
					BigInteger exponent = new BigInteger(value.getValue().stringValue(), 10);
					if (!exponent.equals(certRsakey.getPublicExponent())) {
						continue;
					}
				} else {
					continue;
				}

				// success!
				return new DereferencedFoafSslPrincipal(claimedIdUri,
						  dereferencedSecurely, foafServerCertificates);
			}
		} else if (certPublicKey instanceof DSAPublicKey) {
		} else {
			// what else ?
		}
		return null;
	}

	/**
	 * we are interested in the alternative URI names in the certificates
	 * (perhaps others such as email addresses could also be useful)
	 *
	 * @param cert
	 * @return a list of such URIs
	 */
	public static List<URI> getAlternativeURIName(X509Certificate cert) {
		ArrayList<URI> answers = new ArrayList<URI>();
		try {
			if (cert == null) {
				return answers;
			}
			Collection<List<?>> names = cert.getSubjectAlternativeNames();
			if (names == null) {
				// beurk! this is part of the spec. it can return null
				return answers;
			}
			for (Iterator<List<?>> it = names.iterator(); it.hasNext();) {
				List<?> altNameList = it.next();
				Integer id = (Integer) altNameList.get(0);
				if (id == 6) { // see X509 spec, section 8.3.2.1 these are the
					// URIs!
					Object uristr = altNameList.get(1);
					if (uristr instanceof String) {
						try {
							URI foafid = new URI((String) uristr);
							answers.add(foafid);
						} catch (URISyntaxException e) {
							e.printStackTrace();
						}
					} else {
						// if we are to return other things, such as email and
						// so we would need a more
						// complex structure in the return, perhaps even a class
						// for the X509 cert with
						// more helpful return methods
					}
				}
			}
		} catch (java.security.cert.CertificateParsingException e) {
			e.printStackTrace(); // todo: decide what exception to throw
		}
		return answers;
	}
	static final private char[] hexchars = {'0', '1', '2', '3', '4', '5', '6',
		'7', '8', '9', 'A', 'a', 'B', 'b', 'C', 'c', 'D', 'd', 'E', 'e',
		'F', 'f'};

	static {
		Arrays.sort(hexchars);
	}

	/**
	 * This takes any string and returns in order only those characters that are
	 * part of a hex string
	 *
	 * @param strval
	 *            any string
	 * @return a pure hex string
	 */
	private String cleanHex(String strval) {
		StringBuffer cleanval = new StringBuffer();
		for (char c : strval.toCharArray()) {
			if (Arrays.binarySearch(hexchars, c) >= 0) {
				cleanval.append(c);
			}
		}
		return cleanval.toString();
	}

	private String mimeType(String contentType) {
		int i = contentType.indexOf(';');
		if (i >0) {
			contentType = contentType.substring(0, i);
		} 
		return contentType.trim();
	}
}
