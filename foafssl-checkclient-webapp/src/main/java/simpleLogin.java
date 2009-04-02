
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import net.java.dev.sommer.foafssl.principals.FoafSslPrincipal;
import net.java.dev.sommer.foafssl.verifier.DereferencingFoafSslVerifier;
import org.openrdf.OpenRDFException;

/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
/**
 *
 * @author hjs
 */
public class simpleLogin extends HttpServlet {

	@Override
	protected void service(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		ServletOutputStream out = resp.getOutputStream();
		X509Certificate[] certs = (X509Certificate[]) req.getAttribute("javax.servlet.request.X509Certificate");
		if (certs == null) {
			out.print("No certificate retrieved from server");
		} else {
			try {
				for (X509Certificate cert : certs) {
					out.println(" - " + cert.getSubjectX500Principal().getName());
				}
				X509Certificate clientCert = certs[0];
				DereferencingFoafSslVerifier verifier = new DereferencingFoafSslVerifier();
				out.println("Verified URIs:");
				for (FoafSslPrincipal verifiedUri : verifier.verifyFoafSslCertificate(clientCert)) {
					out.println(" - " + verifiedUri.getUri());
				}
			} catch (OpenRDFException ex) {
				Logger.getLogger(simpleLogin.class.getName()).log(Level.WARNING, null, ex);
			}
		}
	}
}
