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

package net.java.dev.sommer.foafssl.principals;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * This is an X509 certificate claim.
 *
 * A certificate is a claim. Usually by the time this object is created it is clear that the
 * browser has the private key for the claim. But from there on there are still things that
 * need to be proven.
 *
 * The Certificate can have a number of Principals:
 *  - DN
 *  - subject alternatative names, ...
 *
 * some of which may be verifiable, some not.
 *
 * This object collects the proofs about the different names one has, allowing one then to
 * make an estimate of the trust one can have in this principal.
 *
 * This is more of a sketch of an idea. How one would do this in detail is still
 * something that is being explored, and whether this class is the best way to think of the problem
 * is also open.
 *
 * @author Henry Story
 */
public class X509Claim {
    X509Certificate certClaim;
    private LinkedList<Throwable> problemDescription = new LinkedList<Throwable>();
    private List<WebIdClaim> verified = new LinkedList<WebIdClaim>();
    private List<WebIdClaim> problematic = new LinkedList<WebIdClaim>();
    static transient Logger log = Logger.getLogger(X509Claim.class.getName());



    public X509Claim(X509Certificate cert) {
        certClaim = cert;
    }

    public boolean verify() {
        if (!isCurrent()) {
           getProblemDescription().add(new Severe("Certificate is out of date"));
            return false;
           //todo: perhaps that should be optional
        }
        List<URI> candidateUris = getAlternativeURIName(certClaim);

        for (URI candidateUri : candidateUris) {
            WebIdClaim webid = new WebIdClaim(candidateUri,certClaim.getPublicKey());
            boolean ok = webid.verify();
            if (ok) {
                getVerified().add(webid);
            } else {
                getProblematic().add(webid);
            }
        }
        return getVerified().size()>0;
    }

    /**
     *
     * @return true if the certificate is currently valid
     */
    public boolean isCurrent() {
        // here we fail if there is neither a notbefore nor a notafter date
        Date notBeforeDate = certClaim.getNotBefore();
        Date currentDate = new Date();
        if (notBeforeDate == null || currentDate.before(notBeforeDate)) {
            return false;
        }
        Date notAfterDate = certClaim.getNotAfter();
        if (notAfterDate == null || currentDate.after(notAfterDate)) {
            return false;
        }
        return true;
    }



       /**
     * Extracts the URIs in the subject alternative name extension of an X.509
     * certificate (perhaps others such as email addresses could also be
     * useful).
     *
     * @param cert X.509 certificate from which to extract the URIs.
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
        } catch (CertificateParsingException e) {
            // TODO: decide what exception to throw
            log.log(Level.WARNING,
                    "Unable to parse certificate for extracting the subjectAltNames.", e);
        }
        return answers;
    }

    public LinkedList<Throwable> getProblemDescription() {
        return problemDescription;
    }

    public List<WebIdClaim> getVerified() {
        return verified;
    }

    public List<WebIdClaim> getProblematic() {
        return problematic;
    }
}
