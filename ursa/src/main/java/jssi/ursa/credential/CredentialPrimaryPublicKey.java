/*
 *  Copyright 2013 The Apache Software Foundation.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package jssi.ursa.credential;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.math.BigInteger;
import java.util.Map;

/**
 * Issuer's "Public Key" is used to verify the Issuer's signature over the Credential's attributes' values (primary credential).
 */
public class CredentialPrimaryPublicKey {

    @JsonProperty("n")
    public BigInteger n;
    @JsonProperty("s")
    public BigInteger s;
    @JsonProperty("r")
    public Map<String, BigInteger> r;
    @JsonProperty("rctxt")
    public BigInteger rctxt;
    @JsonProperty("z")
    public BigInteger z;

    @JsonCreator
    public CredentialPrimaryPublicKey(@JsonProperty("n") BigInteger n,
                                      @JsonProperty("s") BigInteger s,
                                      @JsonProperty("rctxt") BigInteger rctxt,
                                      @JsonProperty("r") Map<String, BigInteger> r,
                                      @JsonProperty("z") BigInteger z){
        this.n = n;
        this.s = s;
        this.r = r;
        this.rctxt = rctxt;
        this.z = z;
    }
}
