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

package net.java.dev.sommer.foafssl.util;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * An InputStream to protect against one vector of denial of service attacks:
 * incoming pointers to files that are infinitely long.
 *
 * @author Henry Story
 */
public class SafeInputStream extends FilterInputStream {
    final private int maxInput;
    int read = 0;
    int pointer;
    boolean cutshort = false;

    /**
     * Wrap an input stream from which no more than maxInput will be read
     *
     * @param wrapped  the intput stream to read from
     * @param maxInput the max number of bytes to read
     */
    public SafeInputStream(InputStream wrapped, int maxInput) {
        super(wrapped);
        this.maxInput = maxInput;
    }

    @Override
    public int read() throws IOException {
        if (++read > maxInput) {
            cutshort = true;
            return -1;
        }
        return super.read();
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        if (read >= maxInput) {
            cutshort = true;
            return -1;
        }
        len = Math.min(len, maxInput - read);
        int r = super.read(b, off, len);
        read += r;
        return r;
    }

    /**
     * skipping also increments the counter.
     * Other behavior could be imagined. This won't work well on streams that allow rewinding
     *
     * @param n the number of bytes to skip
     * @return the bytes skipped
     * @throws IOException
     */
    @Override
    public long skip(long n) throws IOException {
        n = Math.min(n, maxInput - read);
        long skpd = super.skip(n);
        read += skpd;
        return skpd;
    }

    @Override
    public int available() throws IOException {
        return Math.min(in.available(), maxInput - read);
    }

    /**
     * This is not fool proof.
     *
     * @param readlimit
     */
    @Override
    public void mark(int readlimit) {
        if (markSupported()) {
            pointer = read;
            super.mark(readlimit);
        }
    }

    /**
     * This is not fool proof
     *
     * @throws IOException
     */
    @Override
    public void reset() throws IOException {
        if (markSupported()) {
            read = pointer;
            super.reset();
        }
    }

    /**
     * This wrapped input stream was cut off before the end
     *
     * @return
     */
    public boolean wasCutShort() {
        return cutshort;
    }

    /**
     *
     * @return the maximum input allowed on this stream
     */
    public int getMax() {
        return maxInput;
    }
}
