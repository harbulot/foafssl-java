/**-----------------------------------------------------------------------
  
Copyright (c) 2009, The University of Manchester, United Kingdom.
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

  Author........: Bruno Harbulot

-----------------------------------------------------------------------*/
package uk.ac.manchester.rcs.bruno.samlredirector.misc;

import java.io.InputStream;
import java.util.Arrays;
import java.util.List;

import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.xml.security.credential.Credential;
import org.restlet.data.Request;

/**
 * @author Bruno Harbulot (Bruno.Harbulot@manchester.ac.uk)
 * 
 */
public class RestletRequestInTransportAdapter implements HTTPInTransport {
    private Request request;

    public RestletRequestInTransportAdapter(Request request) {
        this.request = request;
    }

    @Override
    public String getPeerAddress() {
        return this.request.getClientInfo().getAddress();
    }

    @Override
    public String getPeerDomainName() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public InputStream getIncomingStream() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Object getAttribute(String name) {
        return null;
    }

    @Override
    public String getCharacterEncoding() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Credential getLocalCredential() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Credential getPeerCredential() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public boolean isAuthenticated() {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public boolean isConfidential() {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public boolean isIntegrityProtected() {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public void setAuthenticated(boolean arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    public void setConfidential(boolean arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    public void setIntegrityProtected(boolean arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    public String getHeaderValue(String name) {
        return null;
    }

    @Override
    public String getHTTPMethod() {
        return this.request.getMethod().getName();
    }

    @Override
    public String getParameterValue(String name) {
        return request.getResourceRef().getQueryAsForm().getFirstValue(name);
    }

    @Override
    public List<String> getParameterValues(String name) {
        return Arrays.asList(request.getResourceRef().getQueryAsForm().getValuesArray(name));
    }

    @Override
    public int getStatusCode() {
        return -1;
    }

    @Override
    public HTTP_VERSION getVersion() {
        return null;
    }
}
