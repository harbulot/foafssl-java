/*
 * New BSD license: http://opensource.org/licenses/bsd-license.php
 *
 * Copyright (c) 2010
 * Henry Story
 * http://bblfish.net/
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * - Redistributions of source code must retain the above copyright notice,
 *  this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright notice,
 *  this list of conditions and the following disclaimer in the documentation
 *  and/or other materials provided with the distribution.
 * - Neither the name of bblfish.net nor the names of its contributors
 *  may be used to endorse or promote products derived from this software
 *  without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package net.java.dev.sommer.foafssl.verifier;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;

/**
* Created by IntelliJ IDEA.
* User: hjs
* Date: Mar 21, 2010
* Time: 7:45:04 PM
* To change this template use File | Settings | File Templates.
*/
class SettableMimeTypeURLStreamHandler extends URLStreamHandler {
    String mimeType;
    String file;

    public void setUp(String mimeType, String file) {
        this.mimeType = mimeType;
        this.file = file;
    }

    @Override
    protected URLConnection openConnection(final URL u) throws IOException {
        return new HttpURLConnection(u) {

            @Override
            public void disconnect() {
            }

            @Override
            public boolean usingProxy() {
                return false;
            }

            @Override
            public void connect() throws IOException {
            }

            @Override
            public String getContentType() {
                return mimeType;
            }

            @Override
            public InputStream getInputStream() throws IOException {
                return SettableMimeTypeURLStreamHandler.class
                        .getResourceAsStream(file);
            }
        };
    }
}
