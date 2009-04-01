package net.java.dev.sommer.foafssl.principals;

import java.net.URI;
import java.security.cert.Certificate;

/**
 * @author Bruno Harbulot
 */
public class DereferencedFoafSslPrincipal extends FoafSslPrincipal {

	protected final boolean deferencedSecurely;
	protected final Certificate[] foafServerCertificates;

	public DereferencedFoafSslPrincipal(URI uri) {
		this(uri, false);
	}

	public DereferencedFoafSslPrincipal(URI uri, boolean dereferencedSecurely) {
		this(uri, dereferencedSecurely, null);
	}

	public DereferencedFoafSslPrincipal(URI uri, boolean dereferencedSecurely,
			  Certificate[] foafServerCertificates) {
		super(uri);
		this.deferencedSecurely = dereferencedSecurely;
		if (foafServerCertificates != null) {
			this.foafServerCertificates = new Certificate[foafServerCertificates.length];
			for (int i = 0; i < foafServerCertificates.length; i++) {
				this.foafServerCertificates[i] = foafServerCertificates[i];
			}
		} else {
			this.foafServerCertificates = null;
		}
	}

	public boolean isDeferencedSecurely() {
		return this.deferencedSecurely;
	}

	public Certificate[] getFoafServerCertificates() {
		if (this.foafServerCertificates != null) {
			Certificate[] certs = new Certificate[this.foafServerCertificates.length];
			for (int i = 0; i < certs.length; i++) {
				 certs[i] = this.foafServerCertificates[i];
			}
			return certs;
		} else {
			return null;
		}
	}
}
