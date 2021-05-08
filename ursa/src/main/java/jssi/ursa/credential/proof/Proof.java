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

package jssi.ursa.credential.proof;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * Proof is complex crypto structure created by prover over multiple credentials that allows to prove that prover:
 * 1) Knows signature over credentials issued with specific issuer keys (identified by key id)
 * 2) Credential contains attributes with specific values that prover wants to disclose
 * 3) Credential contains attributes with valid predicates that verifier wants the prover to satisfy.
 */
public class Proof {

    public List<SubProof> proofs;
    public AggregatedProof aggregated_proof;

    @JsonCreator
    public Proof(
            @JsonProperty("proofs") List<SubProof> proofs,
            @JsonProperty("aggregated_proof") AggregatedProof aggregated_proof)
    {
        this.proofs = proofs;
        this.aggregated_proof = aggregated_proof;
    }
}
