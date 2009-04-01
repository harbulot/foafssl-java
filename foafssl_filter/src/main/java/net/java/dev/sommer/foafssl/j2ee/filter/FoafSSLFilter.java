package net.java.dev.sommer.foafssl.j2ee.filter;

import java.io.IOException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import net.java.dev.sommer.foafssl.verifier.*;
/**
 * Hello world!
 *
 */
public class FoafSSLFilter implements Filter
{

   public void init(FilterConfig arg0) throws ServletException {
      //do nothing. Perhaps this sets path regexps arguments?
   }

   public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) throws IOException, ServletException {
      new DereferencingFoafSslVerifier();

   }

   public void destroy() {
      //do nothing yet
   }
}
