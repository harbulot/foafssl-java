package net.java.dev.sommer.foafssl.principals;

import java.net.URI;
import java.security.Principal;

/**
 * @author Bruno Harbulot
 */
public abstract class FoafSslPrincipal implements Principal {
    protected final URI uri;

    public FoafSslPrincipal(URI uri) {
	this.uri = uri;
    }

    public URI getUri() {
	return this.uri;
    }

    public String getName() {
	return getUri().toASCIIString();
    }
}
