<%@page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@page import="net.java.dev.sommer.foafssl.login.AbstractIdpServlet"%>
<%@page import="java.util.Collection"%>
<%@page import="net.java.dev.sommer.foafssl.principals.FoafSslPrincipal"%>
<%@page import="java.security.PublicKey"%>
<%@page import="java.security.interfaces.RSAPublicKey"%>
<%@page import="org.bouncycastle.openssl.PEMWriter"%>
<%@page import="java.security.cert.Certificate"%><html>
<head>
<title>FOAF+SSL Identity Provider servlet</title>
</head>
<body>
<h1>FOAF+SSL Identity Provider servlet</h1>
<p>This is a very basic Identity Provider (IdP) for <a
	href='http://esw.w3.org/topic/foaf+ssl'>FOAF+SSL</a>. It identifies a
user connecting using SSL to this service, and returns the <a
	href='http://esw.w3.org/topic/WebID'>WebID</a> of the user to the
service in a secure manner.
</p>

<p>For example, the client that has just loaded this page (you) <%
	@SuppressWarnings("unchecked")
	Collection<? extends FoafSslPrincipal> verifiedWebIDs = (Collection<? extends FoafSslPrincipal>) request
			.getAttribute(AbstractIdpServlet.VERIFIED_WEBID_PRINCIPALS_REQATTR);
	if (verifiedWebIDs == null || verifiedWebIDs.size() == 0) {
%> does not have a verified WebID. To try out this IdP service, create yourself a
certificate using the <a href='http://foaf.me'>http://foaf.me</a>
service.</p>

<%
	} else {
		out.println(" have the following WebIDs:<ul>");
		for (FoafSslPrincipal ids : verifiedWebIDs) {
			out.println("<li><a href='" + ids.getUri() + "'>"
					+ ids.getUri() + "</a></li>");
		}
		out.println("</ul>");
	}
%>
<h3>Getting the WebID</h3>
<h4>Using this Identity Provider</h4>
<p>To use this IdP to authenticate to a service that uses this <em>short redirect</em> method, use the following form:
<form action='' method='get'>Requesting service URL: <input
	type='text' size='80' name='authreqissuer'></input><input type='submit'
	value='Log in to this service provider'></form>
<p>This will send a redirection to the URL of the Service Provider (SP) you have specified in the form above, including a signed 
assertion by this IdP about your WebID.</p>
<p>For example, if the Service Provider's URL is <code>http://foaf.me/index.php</code>, and if this service
can parse the resulting redirect from this IdP service, you could
enter this URL in the form above, which constructs the URL <code>https://foafssl.org/srv/idp?authreqissuer=http://foaf.me/index.php</code>.

This is the URL that you would link to on your home page with a simple <code>&lt;a
href='...'&gt;Login with FOAF+SSL&lt;/a&gt;</code> anchor.

Users who then click on that link will be asked by this IdP to choose one of their
certificates. Upon reception of their certificate, this server will then do
FOAF+SSL authentication, and redirect to <code>http://foaf.me/index.php</code>
with a number of extra url encoded parameter values, as explained below.</p>
<p>The redirected to URL is constructed on the following pattern:<pre><b>$authreqissuer?webid=$webid&amp;ts=$timeStamp</b>&amp;sig=$URLSignature</pre>Where
the above variables have the following meanings:
<ul>
	<li><code>$authreqissuer</code> is the URL passed by the server in
	the initial request.</li>
	<li><code>$webid</code> is the WebID of the user connecting.
	<li><code>$timeStamp</code> is a time stamp in XML Schema format
	(same as used by Atom). This is needed to reduce the ease of developing
	replay attacks.
	<li><code>$URLSignature</code> is the signature of the whole URL
	in bold above.
</ul>
</p>
<h4>Error responses</h4>
<p>In case of error the service gets redirected to <pre>$authreqissuer?error=$code</pre>Where
$code can be either one of
<ul>
	<li><code>nocert</code>: when the client has no cert. This allows
	the SP to propose the client other authentication mechanisms.
	<li><code>IdPError</code>: for some error in the IdP setup. Warn
	the IdP administrator!
	<li>other messages, not standardised yet</li>
</ul>
</p>
<h3>Verifiying the WebId</h3>
<p>In order for the Service Provider (SP) requesting an identity
from this Identity Provider to to be comfortable that the returned WebId
was not altered in transit, the whole URL is signed by this server as
shown above. Here are the public keys and algorithms this server is
using for the SP to verify the url.</p>
<%
	Certificate certificate = (Certificate) request
			.getAttribute(AbstractIdpServlet.SIGNING_CERT_REQATTR);
	PublicKey pubKey = (PublicKey) request
			.getAttribute(AbstractIdpServlet.SIGNING_PUBKEY_REQATTR);

	if (pubKey != null) {
		if ("RSA".equals(pubKey.getAlgorithm())) {
			RSAPublicKey rsaPubKey = (RSAPublicKey) pubKey;
			out
					.println("<p>The signature uses the RSA with SHA-1 algorithm.</p>");
			out
					.println("<p>The public key used by this service that verifies the signature is:");
			RSAPublicKey certRsakey = (RSAPublicKey) pubKey;
			out.println("<ul><li>Key Type: RSA</li>"
					+ "<li>public exponent (decimal): "
					+ certRsakey.getPublicExponent() + "</li>");
			out.println("<li>modulus (decimal): "
					+ certRsakey.getModulus() + "</li></ul>");
		}

		out
				.println("For ease of use, depending on which tool you use, here is the public key in a PEM format:");
		out.println("<ul><li>Public key:<pre>");
		PEMWriter pemWriter = new PEMWriter(out);
		pemWriter.writeObject(pubKey);
		pemWriter.flush();

		out.println("</pre></li>");
		out.println("<li>Certificate with this public key:<pre>");

		pemWriter.writeObject(certificate);
		pemWriter.flush();

		out.println("</pre></li></ul>");
	}
%>
</p>
</body>
</html>