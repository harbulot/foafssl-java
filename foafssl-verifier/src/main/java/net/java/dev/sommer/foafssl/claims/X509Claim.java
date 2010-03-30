/*
 * New BSD license: http://opensource.org/licenses/bsd-license.php
 *
 * Copyright (c) 2010
 * Henry Story
 * http://bblfish.net/
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * - Redistributions of source code must retain the above copyright notice,
 *  this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright notice,
 *  this list of conditions and the following disclaimer in the documentation
 *  and/or other materials provided with the distribution.
 * - Neither the name of bblfish.net nor the names of its contributors
 *  may be used to endorse or promote products derived from this software
 *  without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package net.java.dev.sommer.foafssl.claims;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import net.java.dev.sommer.foafssl.principals.WebIdPrincipal;

/**
 * This is an X.509 certificate claim.
 * 
 * A certificate represents a claim (more so because FOAF+SSL doesn't rely on
 * the PKI verification of this certificate). Usually, by the time this object
 * is created it is clear that the browser has the private key for the claim.
 * But from there on there are still things that need to be proven.
 * 
 * A certificate may contain a number of pieces of information, in particular
 * names, some of which may be verifiable, some not.
 * 
 * This object collects the proofs about the different names one has, allowing
 * one then to make an estimate of the trust one can have in this principal.
 * 
 * This is more of a sketch of an idea. How one would do this in detail is still
 * something that is being explored, and whether this class is the best way to
 * think of the problem is also open.
 * 
 * @author Henry Story
 */
public class X509Claim {
    private final X509Certificate certClaim;
    private final LinkedList<Throwable> problemDescription = new LinkedList<Throwable>();
    private final List<WebIdClaim> verified = new LinkedList<WebIdClaim>();
    private final List<WebIdClaim> problematic = new LinkedList<WebIdClaim>();
    static transient Logger LOG = Logger.getLogger(X509Claim.class.getName());

    public X509Claim(X509Certificate cert) {
        certClaim = cert;
    }

    public boolean verify() {
        return verify(new Date());
    }

    public boolean verify(Date validityDate) {
        if (!isCurrent(validityDate)) {
            getProblemDescription().add(new Severe("Certificate is not currently valid."));
            return false;
        }
        List<URI> candidateUris = getAlternativeURIName(certClaim);

        for (URI candidateUri : candidateUris) {
            WebIdClaim webIdClaim = new WebIdClaim(candidateUri, certClaim.getPublicKey());
            boolean ok = webIdClaim.verify();
            if (ok) {
                getVerified().add(webIdClaim);
            } else {
                getProblematic().add(webIdClaim);
            }
        }
        return getVerified().size() > 0;
    }

    /**
     * Checks whether the certificate is currently valid.
     * 
     * @return true if the certificate is currently valid
     */
    public boolean isCurrent() {
        return isCurrent(new Date());
    }

    /**
     * Checks whether the certificate is valid at a given date.
     * 
     * @param validityDate
     *            date to test
     * @return true if the date is after notBefore and before notAfter.
     */
    public boolean isCurrent(Date validityDate) {
        /*
         * notAfter and notBefore are mandatory in X.509, so these two dates
         * should always be present in a certificate.
         */
        Date notBeforeDate = certClaim.getNotBefore();
        if (notBeforeDate == null || validityDate.before(notBeforeDate)) {
            return false;
        }
        Date notAfterDate = certClaim.getNotAfter();
        if (notAfterDate == null || validityDate.after(notAfterDate)) {
            return false;
        }
        return true;
    }

    /**
     * Extracts the URIs in the subject alternative name extension of an X.509
     * certificate (perhaps others such as email addresses could also be
     * useful).
     * 
     * @param cert
     *            X.509 certificate from which to extract the URIs.
     * @return list of java.net.URIs built from the URIs in the subjectAltName
     *         extension.
     */
    public static List<URI> getAlternativeURIName(X509Certificate cert) {
        ArrayList<URI> answers = new ArrayList<URI>();
        try {
            if (cert == null) {
                return answers;
            }
            Collection<List<?>> names = cert.getSubjectAlternativeNames();
            if (names == null) {
                return answers;
            }
            for (Iterator<List<?>> it = names.iterator(); it.hasNext();) {
                List<?> altNameList = it.next();
                Integer id = (Integer) altNameList.get(0);
                if (id == 6) { // see X.509 spec, section 8.3.2.1 these are the
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
                        /*
                         * if we are to return other things, such as email and
                         * so we would need a more complex structure in the
                         * return, perhaps even a class for the X.509 cert with
                         * more helpful return methods
                         */
                    }
                }
            }
        } catch (CertificateParsingException e) {
            /*
             * TODO: decide what exception to throw (BH: perhaps throwing a
             * CertificateException would be appropriate here?)
             */
            LOG.log(Level.WARNING,
                    "Unable to parse certificate for extracting the subjectAltNames.", e);
        }
        return answers;
    }

    public LinkedList<Throwable> getProblemDescription() {
        return problemDescription;
    }

    public List<WebIdClaim> getVerified() {
        return Collections.unmodifiableList(verified);
    }

    public List<WebIdClaim> getProblematic() {
        return Collections.unmodifiableList(problematic);
    }

    public Collection<? extends WebIdPrincipal> getPrincipals() {
        if (getVerified() != null) {
            ArrayList<WebIdPrincipal> foafSslPrincipals = new ArrayList<WebIdPrincipal>();
            for (WebIdClaim webIdClaim : getVerified()) {
                foafSslPrincipals.add(webIdClaim.getPrincipal());
            }
            return foafSslPrincipals;
        } else {
            return null;
        }
    }
}
