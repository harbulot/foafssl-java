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

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NameNotFoundException;
import javax.naming.NamingException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;

import net.java.dev.sommer.foafssl.verifier.SesameFoafSslVerifier;
import net.java.dev.sommer.foafssl.verifier.FoafSslVerifier;

/**
 * @author Bruno Harbulot (Bruno.Harbulot@manchester.ac.uk)
 * 
 */
public abstract class AbstractIdpServlet extends HttpServlet {
    private static final long serialVersionUID = 2L;

    public static final transient Logger LOG = Logger.getLogger(AbstractIdpServlet.class.getName());

    public final static String CERTIFICATE_JNDI_NAME = "foafsslidp/signingCertificate";
    public final static String PRIVATEKEY_JNDI_NAME = "foafsslidp/signingPrivateKey";

    public final static String KEYSTORE_JNDI_NAME = "foafsslidp/signingKeyStore";

    public final static String KEYSTOREPATH_JNDI_NAME = "foafsslidp/signingKeystorePath";
    public final static String KEYSTORETYPE_JNDI_NAME = "foafsslidp/signingKeystoreType";
    public final static String KEYSTOREPASSWORDARRAY_JNDI_NAME = "foafsslidp/signingKeystorePasswordArray";
    public final static String KEYSTOREPASSWORD_JNDI_NAME = "foafsslidp/signingKeystorePassword";

    public final static String KEYPASSWORDARRAY_JNDI_NAME = "foafsslidp/signingKeyPasswordArray";
    public final static String KEYPASSWORD_JNDI_NAME = "foafsslidp/signingKeyPassword";
    public final static String KEYALIAS_JNDI_NAME = "foafsslidp/signingKeyAlias";

    public final static String KEYSTORE_PATH_INITPARAM = "keystorePath";
    public final static String KEYSTORE_TYPE_INITPARAM = "keystoreType";
    public final static String KEYSTORE_PASSWORD_INITPARAM = "keystorePassword";
    public final static String KEY_PASSWORD_INITPARAM = "keyPassword";
    public final static String ALIAS_INITPARAM = "keyAlias";

    public final static String VERIFIED_WEBID_PRINCIPALS_REQATTR = "net.java.dev.sommer.foafssl.login.verified_webid_principals";
    public final static String SIGNING_CERT_REQATTR = "net.java.dev.sommer.foafssl.login.signing_cert";
    public final static String SIGNING_PUBKEY_REQATTR = "net.java.dev.sommer.foafssl.login.signing_pubkey";

    protected final static FoafSslVerifier FOAF_SSL_VERIFIER = new SesameFoafSslVerifier();

    protected volatile PrivateKey privateKey = null;
    protected volatile PublicKey publicKey = null;
    protected volatile Certificate certificate = null;

    /**
     * Initialises the servlet: loads the keystore/keys to use to sign the
     * assertions and the issuer name.
     */
    @Override
    public void init() throws ServletException {
        super.init();

        KeyStore keyStore = null;

        String keystorePath = getInitParameter(KEYSTORE_PATH_INITPARAM);
        String keystoreType = getInitParameter(KEYSTORE_TYPE_INITPARAM);
        char[] keystorePasswordArray = null;
        char[] keyPasswordArray = null;
        {
            String keystorePassword = getInitParameter(KEYSTORE_PASSWORD_INITPARAM);
            if (keystorePassword != null) {
                keystorePasswordArray = keystorePassword.toCharArray();
            }
            String keyPassword = getInitParameter(KEY_PASSWORD_INITPARAM);
            if (keyPassword != null) {
                keyPasswordArray = keyPassword.toCharArray();
            } else {
                keyPasswordArray = keystorePasswordArray;
            }
        }
        String alias = getInitParameter(ALIAS_INITPARAM);
        Certificate certificate = null;
        PrivateKey privateKey = null;

        try {
            Context initCtx = new InitialContext();
            Context ctx = (Context) initCtx.lookup("java:comp/env");
            try {
                try {
                    certificate = (Certificate) ctx.lookup(CERTIFICATE_JNDI_NAME);
                } catch (NameNotFoundException e) {
                    LOG.log(Level.FINE, "JNDI name not found", e);
                }

                try {
                    privateKey = (PrivateKey) ctx.lookup(PRIVATEKEY_JNDI_NAME);
                } catch (NameNotFoundException e) {
                    LOG.log(Level.FINE, "JNDI name not found", e);
                }

                try {
                    keyStore = (KeyStore) ctx.lookup(KEYSTORE_JNDI_NAME);
                } catch (NameNotFoundException e) {
                    LOG.log(Level.FINE, "JNDI name not found", e);
                }

                try {
                    String jndiKeystorePath = (String) ctx.lookup(KEYSTOREPATH_JNDI_NAME);
                    if (jndiKeystorePath != null) {
                        keystorePath = jndiKeystorePath;
                    }
                } catch (NameNotFoundException e) {
                    LOG.log(Level.FINE, "JNDI name not found", e);
                }
                try {
                    String jndiKeystoreType = (String) ctx.lookup(KEYSTORETYPE_JNDI_NAME);
                    if (jndiKeystoreType != null) {
                        keystoreType = jndiKeystoreType;
                    }
                } catch (NameNotFoundException e) {
                    LOG.log(Level.FINE, "JNDI name not found", e);
                }

                try {
                    String jndiKeystorePassword = (String) ctx.lookup(KEYSTOREPASSWORD_JNDI_NAME);
                    if (jndiKeystorePassword != null) {
                        keystorePasswordArray = jndiKeystorePassword.toCharArray();
                    }
                } catch (NameNotFoundException e) {
                }
                try {
                    char[] jndiKeystorePasswordArray = (char[]) ctx
                            .lookup(KEYSTOREPASSWORDARRAY_JNDI_NAME);
                    if (jndiKeystorePasswordArray != null) {
                        keystorePasswordArray = jndiKeystorePasswordArray;
                    }
                } catch (NameNotFoundException e) {
                    LOG.log(Level.FINE, "JNDI name not found", e);
                }

                try {
                    String jndiKeyPassword = (String) ctx.lookup(KEYPASSWORD_JNDI_NAME);
                    if (jndiKeyPassword != null) {
                        keyPasswordArray = jndiKeyPassword.toCharArray();
                    }
                } catch (NameNotFoundException e) {
                    LOG.log(Level.FINE, "JNDI name not found", e);
                }
                try {
                    char[] jndiKeyPasswordArray = (char[]) ctx.lookup(KEYPASSWORDARRAY_JNDI_NAME);
                    if (jndiKeyPasswordArray != null) {
                        keyPasswordArray = jndiKeyPasswordArray;
                    }
                } catch (NameNotFoundException e) {
                    LOG.log(Level.FINE, "JNDI name not found", e);
                }

                try {
                    String jndiKeyAlias = (String) ctx.lookup(KEYALIAS_JNDI_NAME);
                    if (jndiKeyAlias != null) {
                        alias = jndiKeyAlias;
                    }
                } catch (NameNotFoundException e) {
                    LOG.log(Level.FINE, "JNDI name not found", e);
                }
            } finally {
                if (ctx != null) {
                    ctx.close();
                }
                if (initCtx != null) {
                    initCtx.close();
                }
            }
        } catch (NameNotFoundException e) {
            LOG.log(Level.INFO, "Unable to load JNDI context.", e);
        } catch (NamingException e) {
            LOG.log(Level.INFO, "Unable to load JNDI context.", e);
        }

        if (keyPasswordArray == null) {
            keyPasswordArray = keystorePasswordArray;
        }

        if ((certificate == null) || (privateKey == null)) {
            if (keyStore == null) {
                try {
                    InputStream ksInputStream = null;

                    try {
                        if (keystorePath != null) {
                            ksInputStream = new FileInputStream(keystorePath);
                        }
                        keyStore = KeyStore.getInstance((keystoreType != null) ? keystoreType
                                : KeyStore.getDefaultType());
                        keyStore.load(ksInputStream, keystorePasswordArray);
                    } finally {
                        if (ksInputStream != null) {
                            ksInputStream.close();
                        }
                    }
                } catch (FileNotFoundException e) {
                    LOG
                            .log(Level.SEVERE,
                                    "Error configuring servlet (could not load keystore).", e);
                    throw new ServletException("Could not load keystore.");
                } catch (KeyStoreException e) {
                    LOG
                            .log(Level.SEVERE,
                                    "Error configuring servlet (could not load keystore).", e);
                    throw new ServletException("Could not load keystore.");
                } catch (NoSuchAlgorithmException e) {
                    LOG
                            .log(Level.SEVERE,
                                    "Error configuring servlet (could not load keystore).", e);
                    throw new ServletException("Could not load keystore.");
                } catch (CertificateException e) {
                    LOG
                            .log(Level.SEVERE,
                                    "Error configuring servlet (could not load keystore).", e);
                    throw new ServletException("Could not load keystore.");
                } catch (IOException e) {
                    LOG
                            .log(Level.SEVERE,
                                    "Error configuring servlet (could not load keystore).", e);
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
                    LOG
                            .log(
                                    Level.SEVERE,
                                    "Error configuring servlet, invalid keystore configuration: alias unspecified or couldn't find key at alias: "
                                            + alias);
                    throw new ServletException(
                            "Invalid keystore configuration: alias unspecified or couldn't find key at alias: "
                                    + alias);
                }
                if (privateKey == null) {
                    privateKey = (PrivateKey) keyStore.getKey(alias, keyPasswordArray);
                }
                if (certificate == null) {
                    certificate = keyStore.getCertificate(alias);
                }
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

        this.certificate = certificate;
        this.publicKey = certificate.getPublicKey();
        this.privateKey = privateKey;
    }
}
