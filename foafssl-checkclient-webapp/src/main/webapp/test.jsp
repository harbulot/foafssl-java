<%@page language="java" contentType="text/plain; charset=ISO-8859-1"
	pageEncoding="ISO-8859-1"%>
<%@ page import="java.security.cert.X509Certificate"%>
<%@ page import="javax.security.auth.x500.X500Principal"%>
<%@ page import="java.net.URI"%>
<%@ page
	import="net.java.dev.sommer.foafssl.verifier.DereferencingFoafSslVerifier"%>
<%
	X509Certificate[] certs = (X509Certificate[]) request
			.getAttribute("javax.servlet.request.X509Certificate");
	if (certs == null) {
		out.println("Cannot find any client certificate.");
	} else {
		out.println("Certificate chain:");
		for (X509Certificate cert : certs) {
			out.println(" - "
					+ cert.getSubjectX500Principal().getName());
		}
		X509Certificate clientCert = certs[0];

		DereferencingFoafSslVerifier verifier = new DereferencingFoafSslVerifier();

		out.println("Verified URIs:");
		for (URI verifiedUri : verifier
				.verifyFoafSslCertificate(clientCert)) {
			out.println(" - " + verifiedUri);
		}
	}
%>