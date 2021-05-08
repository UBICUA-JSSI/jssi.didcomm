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

package jssi.credential.request;

import jssi.credential.proof.AttributeInfo;
import jssi.credential.proof.NonRevokedInterval;
import jssi.credential.proof.PredicateInfo;

import java.math.BigInteger;
import java.util.Map;

public class ProofRequestPayload {

    public BigInteger nonce;
    public String name;
    public String version;
    public Map<String, AttributeInfo> requested_attributes;
    public Map<String, PredicateInfo> requested_predicates;
    public NonRevokedInterval non_revoked;

    public ProofRequestPayload(
            BigInteger nonce,
            String name,
            String version,
            Map<String, AttributeInfo> requested_attributes,
            Map<String, PredicateInfo> requested_predicates,
            NonRevokedInterval non_revoked)
    {
        this.nonce = nonce;
        this.name = name;
        this.version = version;
        this.requested_attributes = requested_attributes;
        this.requested_predicates = requested_predicates;
        this.non_revoked = non_revoked;
    }
}
