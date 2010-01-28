/**-----------------------------------------------------------------------
  
Copyright (c) 2009-2010, The University of Manchester, United Kingdom.
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

-----------------------------------------------------------------------*/
package net.java.dev.sommer.foafssl.login;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Collection;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.java.dev.sommer.foafssl.principals.FoafSslPrincipal;

import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.util.encoders.Base64;

/**
 * @author Bruno Harbulot (Bruno.Harbulot@manchester.ac.uk)
 * @author Henry Story
 * 
 */
public class FoafSslCustomIdpServlet extends AbstractIdpServlet {
    private static final long serialVersionUID = 1L;

    public static final transient Logger LOG = Logger.getLogger(FoafSslCustomIdpServlet.class
            .getName());

    public static final String SIGNATURE_PARAMNAME = "sig";
    public static final String SIGALG_PARAMNAME = "sigalg";
    public static final String TIMESTAMP_PARAMNAME = "ts";
    public static final String WEBID_PARAMNAME = "webid";
    public static final String ERROR_PARAMNAME = "error";
    public static final String AUTHREQISSUER_PARAMNAME = "authreqissuer";

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        Collection<? extends FoafSslPrincipal> verifiedWebIDs = null;

        // TODO: should one test that replyTo is a URL?
        String replyTo = request.getParameter(AUTHREQISSUER_PARAMNAME);

        /*
         * Verifies the certificate passed in the request.
         */
        X509Certificate[] certificates = (X509Certificate[]) request
                .getAttribute("javax.servlet.request.X509Certificate");

        if (certificates != null) {
            X509Certificate foafSslCertificate = certificates[0];
            try {
                verifiedWebIDs = FOAF_SSL_VERIFIER.verifyFoafSslCertificate(foafSslCertificate);
            } catch (Exception e) {
                redirect(response, replyTo + "?" + ERROR_PARAMNAME + "="
                        + URLEncoder.encode(e.getMessage(), "UTF-8"));
                return;
            }
        }

        if ((verifiedWebIDs != null) && (verifiedWebIDs.size() > 0)) {
            try {
                String authnResp = createSignedResponse(verifiedWebIDs, replyTo);
                redirect(response, authnResp);
            } catch (InvalidKeyException e) {
                LOG.log(Level.SEVERE, "Error when signing the response.", e);
                redirect(response, replyTo + "?" + ERROR_PARAMNAME + "=IdPError");
            } catch (NoSuchAlgorithmException e) {
                LOG.log(Level.SEVERE, "Error when signing the response.", e);
                redirect(response, replyTo + "?" + ERROR_PARAMNAME + "=IdPError");
            } catch (SignatureException e) {
                LOG.log(Level.SEVERE, "Error when signing the response.", e);
                redirect(response, replyTo + "?" + ERROR_PARAMNAME + "=IdPError");
            }
        } else {
            usage(response, verifiedWebIDs);
        }
    }

    /**
     * 
     * 
     * @param verifiedWebIDs
     *            a list of webIds identifying the user (only the fist will be
     *            used)
     * @param simpleRequestParam
     *            the service that the response is sent to
     * @param privKey
     *            the private key used by this service
     * @return the URL of the response with the webid, timestamp appended and
     *         signed
     * @throws NoSuchAlgorithmException
     * @throws UnsupportedEncodingException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    private String createSignedResponse(Collection<? extends FoafSslPrincipal> verifiedWebIDs,
            String simpleRequestParam) throws NoSuchAlgorithmException,
            UnsupportedEncodingException, InvalidKeyException, SignatureException {
        /*
         * Reads the FoafSsl simple authn request.
         */
        String authnResp = simpleRequestParam;

        String sigAlg = null;
        if ("RSA".equals(privateKey.getAlgorithm())) {
            sigAlg = "SHA1withRSA";
        } else if ("DSA".equals(privateKey.getAlgorithm())) {
            sigAlg = "SHA1withDSA";
        } else {
            throw new NoSuchAlgorithmException("Unsupported key algorithm type.");
        }

        URI webId = verifiedWebIDs.iterator().next().getUri();
        authnResp += "?" + WEBID_PARAMNAME + "="
                + URLEncoder.encode(webId.toASCIIString(), "UTF-8");
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ");
        authnResp += "&" + TIMESTAMP_PARAMNAME + "="
                + URLEncoder.encode(dateFormat.format(Calendar.getInstance().getTime()), "UTF-8");

        String signedMessage = authnResp;
        Signature signature = Signature.getInstance(sigAlg);
        signature.initSign(privateKey);
        signature.update(signedMessage.getBytes("UTF-8"));
        byte[] signatureBytes = signature.sign();
        authnResp += "&" + SIGNATURE_PARAMNAME + "="
                + URLEncoder.encode(new String(Base64.encode(signatureBytes)), "UTF-8");
        return authnResp;
    }

    /**
     * Redirect request to the given url
     * 
     * @param the
     *            response
     * @param respUrl
     *            the response Url to redirect to
     */
    private void redirect(HttpServletResponse response, String respUrl) {
        response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
        response.setHeader("Location", respUrl);
    }

    /**
     * Web page to explain the usage of this servlet. Please improve, by
     * externalising the html.
     */
    private void usage(HttpServletResponse response,
            Collection<? extends FoafSslPrincipal> verifiedWebIDs) throws IOException {
        StringBuffer res = new StringBuffer();
        res
                .append("<html><head><title>FOAF+SSL identity servlet</title></head><body>")
                .append("<h1>FOAF+SSL identity provider servlet</h1>")
                .append(
                        "<p>This is a very basic Identity Provider for <a href='http://esw.w3.org/topic/foaf+ssl'>FOAF+SSL</a>.")
                .append("It identifies a user connecting using SSL to this service, and returns ")
                .append(
                        "the <a href='http://esw.w3.org/topic/WebID'>WebID</a> of the user to the service in a secure manner.")
                .append("The user that just connected right now for example has ");
        if (verifiedWebIDs == null || verifiedWebIDs.size() == 0) {
            res
                    .append(
                            " no verified webIDs. To try out this service create yourself a certificate using ")
                    .append(" the <a href='http://foaf.me'>http://foaf.me</a> service.");
        } else {
            res.append(" the following WebIDs:<ul>");
            for (FoafSslPrincipal ids : verifiedWebIDs) {
                res.append("<li><a href='").append(ids.getUri()).append("'>").append(ids.getUri())
                        .append("</a></li>");
            }
            res.append("</ul>");
        }
        res
                .append("</p>")
                .append("<h3>Getting the WebId</h3>")
                .append("<h4>Getting an identifier</h4>")
                .append("<p>To request identifiacation, use the following form:")
                .append("<form action='' method='get'>")
                .append("Requesting service URL: <input type='text' size='80' name='")
                .append(AUTHREQISSUER_PARAMNAME)
                .append("'></input>")
                .append("<input type='submit' value='Get WebId'>")
                .append("</form>")
                .append("<p>This service just sends a redirect to the cgi given by the '")
                .append(AUTHREQISSUER_PARAMNAME)
                .append("' parameter, the value is the url entered in the above form.</p> ")
                .append(
                        "<p>So for example if you had a script at <code>http://foaf.me/index.php</code> that could parse the ")
                .append(
                        "resulting redirect from this service, you would enter that url in the form above which constructs the URL ")
                .append(
                        "<code>https://foafssl.org/srv/idp?authreqissuer=http://foaf.me/index.php</code>. This is the URL that you would ")
                .append(
                        " link to on your home page with a simple <code>&lt;a href='...'&gt;login with foaf+ssl&lt;/a&gt;</code> anchor. ")
                .append(
                        " Users that then click on that link will be asked by this IDP to choose one of their certificates. ")
                .append(" On receiving their certificate this server will then ")
                .append(
                        "do foaf+ssl authentication, and redirect to <code>http://foaf.me/index.php</code> with a number of extra url ")
                .append(" encoded parameter values, as explained below.</p>").append(
                        "<p>The redirected to URL is constructed on the following pattern:")
                .append("<pre><b>$").append(AUTHREQISSUER_PARAMNAME).append("?").append(
                        WEBID_PARAMNAME).append("=$webid&amp;").append(TIMESTAMP_PARAMNAME).append(
                        "=$timeStamp</b>&amp;").append(SIGNATURE_PARAMNAME)
                .append("=$URLSignature").append("</pre>");
        res
                .append("Where the above variables have the following meanings:")
                .append("<ul><li><code>$")
                .append(AUTHREQISSUER_PARAMNAME)
                .append("</code> is the URL passed by the server in the initial request.</li>")
                .append("<li><code>$webid</code> is the webid of the user connecting.")
                .append(
                        "<li><code>$timeStamp</code> is a time stamp in XML Schema format (same as used by Atom).")
                .append(" This is needed to reduce the ease of developing replay attacks.")
                .append(
                        "<li><code>$URLSignature</code> is the signature of the whole url in bold above.")
                .append("</ul>");
        res
                .append("</p><h4>Error responses</h4>")
                .append("<p>In case of error the service gets redirected to ")
                .append("<pre>$")
                .append(AUTHREQISSUER_PARAMNAME)
                .append("?")
                .append(ERROR_PARAMNAME)
                .append("=$code")
                .append("</pre>")
                .append("Where $code can be either one of ")
                .append(
                        "<ul><li><code>nocert</code>: when the client has no cert. This allows the SP to propose the client")
                .append(" other authentication mechanisms.")
                .append(
                        "<li><code>IdPError</code>: for some error in the IdP setup. Warn the IdP administrator!")
                .append("<li>other messages, not standardised yet").append("</ul>").append("</p>");

        res
                .append("<h3>Verifiying the WebId</h3>")
                .append(
                        "<p>In order for the Service Provider (SP) requesting an identity from this Identity Provider to ")
                .append(
                        "to be comfortable that the returned WebId was not altered in transit, the whole URL is signed by this server")
                .append(
                        " as shown above. Here are the public keys and algorithms this server is using for the SP to verify the")
                .append(" url.</p>");
        if ("RSA".equals(privateKey.getAlgorithm())) {
            res.append("<p>The signature uses the RSA with SHA-1 algorithm.</p>");
            res.append("<p>The public key used by this service that verifies the signature is:");
            RSAPublicKey certRsakey = (RSAPublicKey) publicKey;
            res.append("<ul><li>Key Type: RSA</li>").append("<li>public exponent: ").append(
                    certRsakey.getPublicExponent()).append("</li>");
            res.append("<li>modulus: ").append(certRsakey.getModulus()).append("</li></ul>");
            // res.append("The signature uses the SHA1withRSA algorithm.");
        } else {
            // TODO for other
        }
        res
                .append("For ease of use, depending on which tool you use, here is the public key in a PEM format:");
        res.append("<ul><li>Public key:<pre>");
        response.getWriter().print(res);

        PEMWriter pemWriter = new PEMWriter(response.getWriter());
        pemWriter.writeObject(publicKey);
        pemWriter.flush();

        res = new StringBuffer();
        res.append("</pre></li>");
        res.append("<li>Certificate with this public key:<pre>");
        response.getWriter().print(res);

        pemWriter.writeObject(certificate);
        pemWriter.flush();

        res = new StringBuffer();
        res.append("</pre></li></ul>");
        res.append("</p></body></html>");
        response.getWriter().print(res);
    }
}
