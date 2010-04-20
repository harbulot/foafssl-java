<%@page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@page import="net.java.dev.sommer.foafssl.login.AbstractIdpServlet"%>
<%@page import="java.util.*"%>
<%@page import="net.java.dev.sommer.foafssl.principals.X509Claim"%>
<%@page import="net.java.dev.sommer.foafssl.principals.WebIdClaim"%>
<%@page import="java.security.PublicKey"%>
<%@page import="java.security.interfaces.RSAPublicKey"%>
<%@page import="org.bouncycastle.openssl.PEMWriter"%>
<%@page import="java.security.cert.Certificate"%>
<html>
<head>
<title>WebId Login Service</title>
</head>
<body>
    <%
	@SuppressWarnings("unchecked")
	X509Claim x509Claim =  (X509Claim) request.getAttribute(AbstractIdpServlet.VERIFIED_WEBID_PRINCIPALS_REQATTR);
    %>
    <h1>Dear </h1>


</body>
</html>