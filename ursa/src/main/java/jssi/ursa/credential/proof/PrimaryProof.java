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
import jssi.ursa.credential.*;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class PrimaryProof {

    public PrimaryEqualProof eq_proof;
    public List<PrimaryPredicateInequalityProof> ne_proofs;

    @JsonCreator
    public PrimaryProof(
            @JsonProperty("eq_proofs") PrimaryEqualProof eq_proof,
            @JsonProperty("ne_proofs") List<PrimaryPredicateInequalityProof> ne_proofs)
    {
        this.eq_proof = eq_proof;
        this.ne_proofs = ne_proofs;
    }

    public static PrimaryInitProof init(
            Map<String, BigInteger> common_attributes,
            CredentialPrimaryPublicKey credentialPrimaryPublicKey,
            PrimaryCredentialSignature primaryCredentialSignature,
            CredentialValues credentialValues,
            CredentialSchema credentialSchema,
            NonCredentialSchema nonCredentialSchema,
            SubProofRequest subProofRequest,
            BigInteger m2_tilde)
    {

        PrimaryEqualInitProof eq_proof = PrimaryEqualProof.init(
                common_attributes,
                credentialPrimaryPublicKey,
                primaryCredentialSignature,
                credentialSchema,
                nonCredentialSchema,
                subProofRequest,
                m2_tilde);

        List<PrimaryPredicateInequalityInitProof> ne_proofs = new ArrayList<>();

        for (Predicate predicate : subProofRequest.predicates) {
            PrimaryPredicateInequalityInitProof ne_proof = PrimaryPredicateInequalityProof.init(
                    credentialPrimaryPublicKey,
                    eq_proof.m_tilde,
                    credentialValues,
                    predicate);
            ne_proofs.add(ne_proof);
        }

        return new PrimaryInitProof(eq_proof, ne_proofs);
    }

    public static PrimaryProof finalize(
            PrimaryInitProof primaryInitProof,
            BigInteger challenge,
            CredentialSchema credentialSchema,
            NonCredentialSchema nonCredentialSchema,
            CredentialValues credentialValues,
            SubProofRequest subProofRequest)
    {

        PrimaryEqualProof eq_proof = PrimaryEqualProof.finalize(
                primaryInitProof.eq_proof,
                challenge,
                credentialSchema,
                nonCredentialSchema,
                credentialValues,
                subProofRequest);

        List<PrimaryPredicateInequalityProof> ne_proofs = new ArrayList<>();

        for(PrimaryPredicateInequalityInitProof init_ne_proof : primaryInitProof.ne_proofs) {
            PrimaryPredicateInequalityProof ne_proof = PrimaryPredicateInequalityProof.finalize(challenge, init_ne_proof, eq_proof);
            ne_proofs.add(ne_proof);
        }

        return new PrimaryProof(eq_proof, ne_proofs);
    }



    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        PrimaryProof that = (PrimaryProof) o;

        if (!eq_proof.equals(that.eq_proof)) return false;
        return ne_proofs.equals(that.ne_proofs);
    }
}
