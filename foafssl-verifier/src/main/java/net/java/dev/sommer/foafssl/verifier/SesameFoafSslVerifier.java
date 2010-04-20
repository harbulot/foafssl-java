/*
New BSD license: http://opensource.org/licenses/bsd-license.php

Copyright (c) 2008-2009 Sun Microsystems, Inc.
901 San Antonio Road, Palo Alto, CA 94303 USA. 
All rights reserved.


Redistribution and use in source and binary forms, with or without 
modification, are permitted provided that the following conditions are met:

- Redistributions of source code must retain the above copyright notice, 
this list of conditions and the following disclaimer.
- Redistributions in binary form must reproduce the above copyright notice, 
this list of conditions and the following disclaimer in the documentation 
and/or other materials provided with the distribution.
- Neither the name of Sun Microsystems, Inc. nor the names of its contributors
may be used to endorse or promote products derived from this software 
without specific prior written permission.

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
 */
package net.java.dev.sommer.foafssl.verifier;

import net.java.dev.sommer.foafssl.cache.GraphCache;
import net.java.dev.sommer.foafssl.cache.GraphCacheLookup;
import net.java.dev.sommer.foafssl.principals.WebIdClaim;
import org.openrdf.model.Literal;
import org.openrdf.model.Resource;
import org.openrdf.model.Value;
import org.openrdf.model.ValueFactory;
import org.openrdf.query.*;
import org.openrdf.repository.RepositoryException;
import org.openrdf.repository.sail.SailRepositoryConnection;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * This class verifies FOAF+SSL certificates by dereferencing the FOAF file at
 * the given Web ID URI.
 *
 * @author Henry Story.
 * @author Bruno Harbulot.
 */
public class SesameFoafSslVerifier extends FoafSslVerifier {
    final static String cert = "http://www.w3.org/ns/auth/cert#";
    final static String xsd = "http://www.w3.org/2001/XMLSchema#";

    static transient Logger log = Logger.getLogger(SesameFoafSslVerifier.class.getName());


    public boolean verify(WebIdClaim webid) {


        GraphCache cache = GraphCacheLookup.getCache();

        //do a check that this is indeed a URL first
        SailRepositoryConnection rep = cache.fetch(webid);
        if (rep == null) return false;

        PublicKey publicKey = webid.getVerifiedPublicKey();

        if (publicKey instanceof RSAPublicKey) {
            RSAPublicKey certRsakey = (RSAPublicKey) publicKey;
            TupleQuery query = null;
            try {
                query = rep.prepareTupleQuery(QueryLanguage.SPARQL,
                        "PREFIX cert: <http://www.w3.org/ns/auth/cert#>"
                                + "PREFIX rsa: <http://www.w3.org/ns/auth/rsa#>"
                                + "SELECT ?m ?e ?mod ?exp "
                                + "WHERE { "
                                + "   [] cert:identity ?agent ;"
                                + "        rsa:modulus ?m ;"
                                + "        rsa:public_exponent ?e ."
                                + "   OPTIONAL { ?m cert:hex ?mod . }"
                                + "   OPTIONAL { ?e cert:decimal ?exp . }"
                                + "}");
            } catch (MalformedQueryException e) {
                log.log(Level.SEVERE,"Error in Query String!",e);
                webid.fail("SERVER ERROR - Please warn administrator");
                return false;
            } catch (RepositoryException e) {
                log.log(Level.SEVERE,"Error with repository",e);
                webid.fail("SERVER ERROR - Please warn administrator");
                return false;
            }

            ValueFactory vf = rep.getValueFactory();
            query.setBinding("agent", vf.createURI(webid.getWebId().toString()));
            TupleQueryResult answer = null;
            try {
                answer = query.evaluate();
            } catch (QueryEvaluationException e) {
               log.log(Level.SEVERE,"Error evaluating Query",e);
               webid.fail("SERVER ERROR - Please warn administrator");
               return false;
            }
            try {
                while (answer.hasNext()) {
                    BindingSet bindingSet = answer.next();

                    //1. find the exponent
                    BigInteger exp = toInteger(bindingSet.getBinding("e"), cert + "decimal", bindingSet.getBinding("exp"));
                    if (exp == null || !exp.equals(certRsakey.getPublicExponent())) {
                        continue;
                    }

                    //2. Find the modulus
                    BigInteger mod = toInteger(bindingSet.getBinding("m"), cert + "hex", bindingSet.getBinding("mod"));
                    if (mod == null || !mod.equals(certRsakey.getModulus())) {
                        continue;
                    }

                    // success!
                    return true;
                }
            } catch (QueryEvaluationException e) {
                log.log(Level.SEVERE,"Error accessing query results",e);
                webid.fail("SERVER ERROR - Please warn administrator");
                return false;
            }
        } else if (publicKey instanceof DSAPublicKey) {
        } else {
            // what else ?
        }
        return false;
    }


       /**
     * Transform an RDF representation of a number into a BigInteger
     * <p/>
     * Passes a statement as two bindings and the relation between them.
     * The subject is the number.
     * If num is already a literal number, that is returned, otherwise if
     * enough information from the relation to optstr exists, that is used.
     *
     * @param num    the number node
     * @param optRel name of the relation to the literal
     * @param optstr the literal representation if it exists
     * @return the big integer that num represents, or null if undetermined
     */
    static BigInteger toInteger(Binding num, String optRel, Binding optstr) {
        if (null == num) return null;
        Value numVal = num.getValue();
        if (numVal instanceof Literal) {  //we do in fact have "ddd"^^type
            Literal ln = (Literal) numVal;
            String type = ln.getDatatype().toString();
            return toInteger_helper(ln.getLabel(), type);
        } else if (numVal instanceof Resource) { //we had _:n type "ddd" .
            Value strVal = optstr.getValue();
            if (strVal != null && strVal instanceof Literal) {
                Literal ls = (Literal) strVal;
                return toInteger_helper(ls.getLabel(), optRel);
            }
        }
        return null;
    }

    /**
     * This transforms a literal into a number if possible
     * ie, it returns the BigInteger of "ddd"^^type
     *
     * @param num  the string representation of the number
     * @param type the type of the string representation
     * @return the number
     */
    private static BigInteger toInteger_helper(String num, String type) {
        if (type.equals(cert + "decimal") || type.equals(cert + "int") ||
                type.equals(xsd + "integer") || type.equals(xsd + "int") ||
                type.equals(xsd + "nonNegativeInteger")) { //cert:decimal is deprecated
            return new BigInteger(num.trim(), 10);
        } else if (type.equals(cert + "hex")) {
            String strval = cleanHex(num);
            return new BigInteger(strval, 16);
        } else {
            //it could be some other encoding - one should really write a special literal transformation class
        }
        return null;
    }



    static final private char[] hexchars = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A',
            'a', 'B', 'b', 'C', 'c', 'D', 'd', 'E', 'e', 'F', 'f'};

    static {
        Arrays.sort(hexchars);
    }

    /**
     * This takes any string and returns in order only those characters that are
     * part of a hex string
     *
     * @param strval any string
     * @return a pure hex string
     */

    private static String cleanHex(String strval) {
        StringBuffer cleanval = new StringBuffer();
        for (char c : strval.toCharArray()) {
            if (Arrays.binarySearch(hexchars, c) >= 0) {
                cleanval.append(c);
            }
        }
        return cleanval.toString();
    }

}
