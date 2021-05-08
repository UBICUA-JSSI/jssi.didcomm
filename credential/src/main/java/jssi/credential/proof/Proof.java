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

package jssi.credential.proof;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class Proof {
    public jssi.ursa.credential.proof.Proof proof;
    public RequestedProof requested_proof;
    public List<Identifier> identifiers;

    @JsonCreator
    public Proof(
            @JsonProperty("proof") jssi.ursa.credential.proof.Proof proof,
            @JsonProperty("requested_proof") RequestedProof requested_proof,
            @JsonProperty("identifiers") List<Identifier> identifiers)
    {
        this.proof = proof;
        this.requested_proof = requested_proof;
        this.identifiers = identifiers;
    }
}
