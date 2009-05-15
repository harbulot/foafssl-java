/**-----------------------------------------------------------------------
  
Copyright (c) 2009, The University of Manchester, United Kingdom.
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

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Collection;
import java.util.Enumeration;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NameNotFoundException;
import javax.naming.NamingException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.tomcat.util.net.SSLSessionManager;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.util.encoders.Base64;

import net.java.dev.sommer.foafssl.principals.FoafSslPrincipal;
import net.java.dev.sommer.foafssl.verifier.DereferencingFoafSslVerifier;
import net.java.dev.sommer.foafssl.verifier.FoafSslVerifier;

/**
 * @author Bruno Harbulot (Bruno.Harbulot@manchester.ac.uk)
 * 
 */
public class IdpServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;

    public static final transient Logger LOG = Logger.getLogger(IdpServlet.class.getName());

    public static final String SIGNATURE_PARAMNAME = "sig";
    public static final String SIGALG_PARAMNAME = "sigalg";
    public static final String TIMESTAMP_PARAMNAME = "ts";
    public static final String WEBID_PARAMNAME = "webid";
    public static final String ERROR_PARAMNAME = "error";
    public static final String AUTHREQISSUER_PARAMNAME = "authreqissuer";
    public static final String LOGOUT_PARAMNAME = "logout";

    public final static String KEYSTORE_JNDI_INITPARAM = "keystore";
    public final static String DEFAULT_KEYSTORE_JNDI_INITPARAM = "keystore/signingKeyStore";
    public final static String KEYSTORE_PATH_INITPARAM = "keystorePath";
    public final static String KEYSTORE_TYPE_INITPARAM = "keystoreType";
    public final static String KEYSTORE_PASSWORD_INITPARAM = "keystorePassword";
    public final static String KEY_PASSWORD_INITPARAM = "keyPassword";
    public final static String ALIAS_INITPARAM = "keyAlias";

    private static FoafSslVerifier FOAF_SSL_VERIFIER = new DereferencingFoafSslVerifier();

    private PrivateKey privateKey = null;
    private PublicKey publicKey = null;
    private Certificate certificate = null;

    /**
     * Initialises the servlet: loads the keystore/keys to use to sign the
     * assertions and the issuer name.
     */
    @Override
    public void init() throws ServletException {
        KeyStore keyStore = null;

        String keystoreJdniName = getInitParameter(KEYSTORE_JNDI_INITPARAM);
        if (keystoreJdniName == null) {
            keystoreJdniName = DEFAULT_KEYSTORE_JNDI_INITPARAM;
        }
        String keystorePath = getInitParameter(KEYSTORE_PATH_INITPARAM);
        String keystoreType = getInitParameter(KEYSTORE_TYPE_INITPARAM);
        String keystorePassword = getInitParameter(KEYSTORE_PASSWORD_INITPARAM);
        String keyPassword = getInitParameter(KEY_PASSWORD_INITPARAM);
        if (keyPassword == null)
            keyPassword = keystorePassword;
        String alias = getInitParameter(ALIAS_INITPARAM);

        try {
            Context ctx = null;
            try {
                keyStore = (KeyStore) new InitialContext().lookup("java:comp/env/"
                        + keystoreJdniName);

            } finally {
                if (ctx != null) {
                    ctx.close();
                }
            }
        } catch (NameNotFoundException e) {
        } catch (NamingException e) {
            LOG.log(Level.SEVERE, "Error configuring servlet.", e);
            throw new ServletException(e);
        }
        if (keyStore == null) {
            try {
                InputStream ksInputStream = null;

                try {
                    if (keystorePath != null) {
                        ksInputStream = new FileInputStream(keystorePath);
                    }
                    keyStore = KeyStore.getInstance((keystoreType != null) ? keystoreType
                            : KeyStore.getDefaultType());
                    keyStore.load(ksInputStream, keystorePassword != null ? keystorePassword
                            .toCharArray() : null);
                } finally {
                    if (ksInputStream != null) {
                        ksInputStream.close();
                    }
                }
            } catch (FileNotFoundException e) {
                LOG.log(Level.SEVERE, "Error configuring servlet (could not load keystore).", e);
                throw new ServletException("Could not load keystore.");
            } catch (KeyStoreException e) {
                LOG.log(Level.SEVERE, "Error configuring servlet (could not load keystore).", e);
                throw new ServletException("Could not load keystore.");
            } catch (NoSuchAlgorithmException e) {
                LOG.log(Level.SEVERE, "Error configuring servlet (could not load keystore).", e);
                throw new ServletException("Could not load keystore.");
            } catch (CertificateException e) {
                LOG.log(Level.SEVERE, "Error configuring servlet (could not load keystore).", e);
                throw new ServletException("Could not load keystore.");
            } catch (IOException e) {
                LOG.log(Level.SEVERE, "Error configuring servlet (could not load keystore).", e);
                throw new ServletException("Could not load keystore.");
            }
        }

        try {
            if (alias == null) {
                Enumeration<String> aliases = keyStore.aliases();
                while (aliases.hasMoreElements()) {
                    String tempAlias = aliases.nextElement();
                    if (keyStore.isKeyEntry(tempAlias)) {
                        alias = tempAlias;
                        break;
                    }
                }
            }
            if (alias == null) {
                LOG.log(Level.SEVERE,
                                "Error configuring servlet, invalid keystore configuration: alias unspecified or couldn't find key at alias: "
                                        + alias);
                throw new ServletException(
                        "Invalid keystore configuration: alias unspecified or couldn't find key at alias: "
                                + alias);
            }
            privateKey = (PrivateKey) keyStore.getKey(alias, keyPassword != null ? keyPassword
                    .toCharArray() : null);
            certificate = keyStore.getCertificate(alias);
            publicKey = certificate.getPublicKey();
        } catch (UnrecoverableKeyException e) {
            LOG.log(Level.SEVERE, "Error configuring servlet (could not load keystore).", e);
            throw new ServletException("Could not load keystore.");
        } catch (KeyStoreException e) {
            LOG.log(Level.SEVERE, "Error configuring servlet (could not load keystore).", e);
            throw new ServletException("Could not load keystore.");
        } catch (NoSuchAlgorithmException e) {
            LOG.log(Level.SEVERE, "Error configuring servlet (could not load keystore).", e);
            throw new ServletException("Could not load keystore.");
        }
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        Collection<? extends FoafSslPrincipal> verifiedWebIDs = null;

        boolean logout=false;
        if ("now".equals(request.getParameter(LOGOUT_PARAMNAME))) {
           SSLSessionManager s =(SSLSessionManager) request.getAttribute("javax.servlet.request.ssl_session_mgr");
           if (s != null) {
//           should I also invalidate http sessions here?
//           HttpSession sess = request.getSession(false);
//           if (sess!=null) sess.invalidate();
              s.invalidateSession();
              logout = true;
           } else {
              LOG.log(Level.SEVERE,"No org.apache.tomcat.util.SSLSessionManager!");
           }
           response.setHeader("Connection", "close");
        }

        // TODO: should one test that replyTo is a URL?
        String replyTo = request.getParameter(AUTHREQISSUER_PARAMNAME);
        if (replyTo == null || "".equals(replyTo)) {
               usage(response, null);
               return;
        } else if (logout) {
           redirect(response,replyTo);
           return;
        }

        /*
         * Verifies the certificate passed in the request.
         */
        X509Certificate[] certificates = (X509Certificate[]) request
                .getAttribute("javax.servlet.request.X509Certificate");

        if (certificates == null) {
           if ( brokenBrowser(request)) {
              //this works on a patched tomcat server to force fetch the certificate
               certificates = (X509Certificate[]) request.getAttribute("javax.servlet.request.ForceX509Certificate");
           }
        }

        if (certificates != null) {
            X509Certificate foafSslCertificate = certificates[0];
            try {
                verifiedWebIDs = FOAF_SSL_VERIFIER.verifyFoafSslCertificate(foafSslCertificate);
            } catch (Exception e) {
                redirect(response,replyTo+"?"+ERROR_PARAMNAME+"="+URLEncoder.encode(e.getMessage()));
                return;
            }
        }

        if ((verifiedWebIDs != null) && (verifiedWebIDs.size() > 0)) {
            try {
                    String authnResp = createSignedResponse(verifiedWebIDs, replyTo);
                    redirect(response, authnResp);
            } catch (InvalidKeyException e) {
                LOG.log(Level.SEVERE, "Error when signing the response.", e);
                redirect(response, replyTo+"?"+ERROR_PARAMNAME+"=IdPError");
            } catch (NoSuchAlgorithmException e) {
                LOG.log(Level.SEVERE, "Error when signing the response.", e);
                redirect(response, replyTo+"?"+ERROR_PARAMNAME+"=IdPError");
            } catch (SignatureException e) {
                LOG.log(Level.SEVERE, "Error when signing the response.", e);
                redirect(response, replyTo+"?"+ERROR_PARAMNAME+"=IdPError");
            }
        } else {
                redirect(response,noCertError(replyTo));
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
         * Reads the FoafSsl simple auth request.
         */
        String authnResp = simpleRequestParam;

        String sigAlg = null;
        if ("RSA".equals(privateKey.getAlgorithm())) {
            sigAlg = "SHA1withRSA";
            // sigAlgUri = "rsa-sha1";
        } else if ("DSA".equals(privateKey.getAlgorithm())) {
            sigAlg = "SHA1withDSA";
            // sigAlgUri = "dsa-sha1";
        } else {
            throw new NoSuchAlgorithmException("Unsupported key algorithm type.");
        }

        URI webId = verifiedWebIDs.iterator().next().getUri();
        authnResp += "?" + WEBID_PARAMNAME + "="
                + URLEncoder.encode(webId.toASCIIString(), "UTF-8");
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ");
        authnResp += "&" + TIMESTAMP_PARAMNAME + "="
                + URLEncoder.encode(dateFormat.format(Calendar.getInstance().getTime()), "UTF-8");
        // authnResp += "&" + SIGALG_PARAMNAME + "=" +
        // URLEncoder.encode(sigAlgUri, "UTF-8");

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
    * @param the response
    * @param respUrl the response Url to redirect to
    */
   private void redirect(HttpServletResponse response, String respUrl) {
      response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
      response.setHeader("Location", respUrl);
   }

   /**
    * create a URL to which the service will be redirected
    * @param replyTo
    * @return a url to redirect to
    */
   private String noCertError(String replyTo) {
      return replyTo+"?"+ERROR_PARAMNAME+"=nocert";
   }


    /**
     * Web page to explain the usage of this servlet. Please improove, by
     * externalising the html.
     */
    private void usage(HttpServletResponse response,
            Collection<? extends FoafSslPrincipal> verifiedWebIDs) throws IOException {
        StringBuffer res = new StringBuffer();
        res.append("<html><head><title>FOAF+SSL identity servlet</title></head><body>")
                .append("<h1>FOAF+SSL identity provider servlet</h1>")
                .append("<p>This is a very basic Identity Provider for <a href='http://esw.w3.org/topic/foaf+ssl'>FOAF+SSL</a>.")
                .append("It identifies a user connecting using SSL to this service, and returns ")
                .append("the <a href='http://esw.w3.org/topic/WebID'>WebID</a> of the user to the service in a secure manner.")
                .append("The user that just connected right now for example has ");
        if (verifiedWebIDs==null || verifiedWebIDs.size() == 0) {
            res.append(" no verified webIDs. To try out this service create yourself a certificate using ")
               .append(" <a href='http://test.foafssl.org/cert/'>this service</a>.");
        } else {
            res.append(" the following WebIDs:<ul>");
            for (FoafSslPrincipal ids : verifiedWebIDs) {
                res.append("<li><a href='").append(ids.getUri()).append("'>").append(ids.getUri())
                        .append("</a></li>");
            }
            res.append("</ul>");
        }
        res.append("</p>")
                .append("<h3>Getting the WebId</h3>")
                .append("<h4>Getting an identifier</h4>")
                .append("<p>To request identifiacation, use the following form:")
                .append("<form action='' method='get'>")
                .append("Requesting service URL: <input type='text' size='80' name='")
                .append(AUTHREQISSUER_PARAMNAME).append("'></input>")
                .append("<input type='submit' value='Get WebId'>")
                .append("</form>")
                .append("<p>This service just sends a redirect to the service given by the '")
                .append(AUTHREQISSUER_PARAMNAME).append("' parameter, the value is the url entered in the above form.</p> ")
                .append("<p>The redirected to URL is constructed on the following pattern:")
                .append("<pre><b>$").append(AUTHREQISSUER_PARAMNAME).append("?").append(WEBID_PARAMNAME)
                .append("=$webid&amp;").append(TIMESTAMP_PARAMNAME).append("=$timeStamp</b>&amp;")
                .append(SIGNATURE_PARAMNAME).append("=$URLSignature").append("</pre>");
        res.append("Where the above variables have the following meanings:")
                .append("<ul><li><code>$")
                .append(AUTHREQISSUER_PARAMNAME)
                .append("</code> is the URL passed by the server in the initial request.</li>")
                .append("<li><code>$webid</code> is the webid of the user connecting.")
                .append("<li><code>$timeStamp</code> is a time stamp in XML Schema format (same as used by Atom).")
                .append(" This is needed to reduce the ease of developing replay attacks.")
                .append("<li><code>$URLSignature</code> is the signature of the whole url in bold above.")
                .append("</ul>");
        res.append("</p><h4>Error responses</h4>")
                .append("<p>In case of error the service gets redirected to ")
                .append("<pre>$").append(AUTHREQISSUER_PARAMNAME).append("?").append(ERROR_PARAMNAME).append("=$code")
                .append("</pre>")
                .append("Where $code can be either one of ")
                .append("<ul><li><code>nocert</code>: when the client has no cert. This allows the SP to propose the client")
                .append(" other authentication mechanisms.")
                .append("<li><code>IdPError</code>: for some error in the IdP setup. Warn the IdP administrator!")
                .append("<li>other messages, not standardised yet")
                .append("</ul>")
                .append("</p>");
        res.append("<h3>To Logout</h3>")
                .append("<p>A user may wish to logout from a service provider, if only in order to assume a different persona.")
                .append(" If the SSL session with this server is not closed, then any attempt to relogin")
                .append(" using this will immediately return the exact same identity (at least for the validity period of the ")
                .append(" ssl session.</p>")
                .append(" <p>To logout use the following form:")
                .append("<form action='' method='get'>")
                .append("Requesting Service URL: <input type='text' size='80' name='")
                .append(AUTHREQISSUER_PARAMNAME).append("'></input>")
                .append("<input type='hidden' name='").append(LOGOUT_PARAMNAME).append("' value='now'/>\n")
                .append("<input type='submit' value='logout from here'>")
                .append("</form></p>")
                .append("<p>The url generated will be something like the following:")
                .append("<pre>...?").append(LOGOUT_PARAMNAME).append("=now&amp;").append(AUTHREQISSUER_PARAMNAME).append("=http://...</pre>");
        res.append("<h3>Verifiying the WebId</h3>")
                .append("<p>In order for the Service Provider (SP) requesting an identity from this Identity Provider to ")
                .append("to be comfortable that the returned WebId was not altered in transit, the whole URL is signed by this server")
                .append(" as shown above. Here are the public keys and algorithms this server is using for the SP to verify the")
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
        res.append("For ease of use, depending on which tool you use, here is the public key in a PEM format:");
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

    /**
     * the iPhone browser requires one to force the connection
     * and so do various versions of Safari... (not tested yet)
     */
   private boolean brokenBrowser(HttpServletRequest request) {
      String ua =request.getHeader("User-Agent");
      if (ua == null) return false;
      return (ua.contains("iPhone") && ua.contains("os 2_2"));
   }

 
}
