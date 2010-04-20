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
<h1>WebId Login Service</h1>
<p>This is a very basic Identity Provider (IdP) for <a
	href='http://esw.w3.org/topic/foaf+ssl'>FOAF+SSL</a>. It identifies a
user connecting using SSL to this service, and returns the <a
	href='http://esw.w3.org/topic/WebID'>WebID</a> of the user to the
service in a secure manner.
</p>

<%
	@SuppressWarnings("unchecked")
	X509Claim x509Claim =  (X509Claim) request.getAttribute(AbstractIdpServlet.VERIFIED_WEBID_PRINCIPALS_REQATTR);
	if (x509Claim == null) {
%> 
<p> We did not receive a certificate from you at all.</p> 

<p> If you do not have a WebID, you can create one yourself using any of a number
    Identity Providers, of which some can be found <a href="http://esw.w3.org/Foaf%2Bssl/IDP">on this list</a>.
</p><!-- TODO: Add some logic to send back to a specific page of the calling provider -->
<%
    } else if (x509Claim.getVerified().size()==0)  {
%>
<p> We received your certificate but were not able to verify it.</p>
<%
      List<WebIdClaim> prob_wids = x509Claim.getProblematic();
      if (prob_wids.size() > 0) {
%>
<p>You sent us <%= prob_wids.size() %> WebIds. We had the following problem processing it.</p>
<ul>
    <% for (WebIdClaim wid: prob_wids) { %>
    <li>
        <%= wid.getWebId() %> which has the following problem:
        <ul>
            <% for ( Throwable t: wid.getProblems() ) { %>
            <li>
                <%= t.getMessage() %>
            </li>
            <% } %>
        </ul>
    </li>
    <% } %>
</ul>
<!-- todo try again -->
</body>
</html>