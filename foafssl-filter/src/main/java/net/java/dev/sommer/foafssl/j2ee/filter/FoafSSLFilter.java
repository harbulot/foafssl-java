package net.java.dev.sommer.foafssl.j2ee.filter;

import java.io.IOException;
import java.io.PrintStream;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import net.java.dev.sommer.foafssl.claims.WebIdClaim;
import net.java.dev.sommer.foafssl.claims.X509Claim;

/**
 * Hello world!
 */
public class FoafSSLFilter implements Filter {

    public static final String WEBIDCLAIMS_ATTR_NAME = "net.java.dev.sommer.foafssl.j2ee.webidclaims";

    public void init(FilterConfig arg0) throws ServletException {
        // do nothing. Perhaps this sets path regexps arguments?
    }

    public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
            throws IOException, ServletException {
        X509Certificate[] certs = (X509Certificate[]) req
                .getAttribute("javax.servlet.request.X509Certificate");
        Collection<? extends WebIdClaim> pls = null;
        try {
            X509Claim x509Claim = new X509Claim(certs[0]);
            if (x509Claim.verify()) {
                pls = x509Claim.getVerified();
                if (pls == null || pls.size() == 0) {
                    resp.getOutputStream().write("No foaf+ssl certificates".getBytes());
                    return;
                }
            }
        } catch (Exception ex) {
            Logger.getLogger(FoafSSLFilter.class.getName()).log(Level.SEVERE, null, ex);
            resp.getOutputStream().write("cought error doing verification:".getBytes());
            ex.printStackTrace(new PrintStream(resp.getOutputStream()));
            return;
        }
        req.setAttribute(WEBIDCLAIMS_ATTR_NAME, pls);
        chain.doFilter(req, resp);
    }

    public void destroy() {
        // do nothing yet
    }
}
