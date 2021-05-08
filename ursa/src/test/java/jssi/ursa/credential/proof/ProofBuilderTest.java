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

import jssi.ursa.credential.*;
import jssi.ursa.credential.issuer.IssuerEmulator;
import jssi.ursa.credential.prover.ProverEmulator;
import jssi.ursa.pair.CryptoException;
import org.junit.jupiter.api.Test;


import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ProofBuilderTest {

    private ProverEmulator prover = new ProverEmulator();
    private IssuerEmulator issuer = new IssuerEmulator();

    @Test
    void initEqProof() throws CryptoException {
        Map<String, BigInteger> common_attributes = new HashMap<>();
        common_attributes.put("master_secret", prover.m1_t());
        CredentialPrimaryPublicKey pk = issuer.getCredentialPrimaryPublicKey();
        CredentialSchema cred_schema = issuer.getCredentialSchema();
        NonCredentialSchema non_cred_schema_elems = issuer.getNonCredentialSchema();
        PrimaryCredentialSignature credential = prover.getPrimaryCredentialSignature();
        SubProofRequest sub_proof_request = prover.getSubProofRequest();

        BigInteger m2_tilde = new BigInteger(1, prover.getNonRevocationInitProof().tau_list_params.m2.toBytes());

        PrimaryEqualInitProof init_eq_proof = PrimaryEqualProof.init(
                common_attributes,
                pk,
                credential,
                cred_schema,
                non_cred_schema_elems,
                sub_proof_request,
                m2_tilde);

        assertEquals(init_eq_proof, prover.getPrimaryEqInitProof());

    }

    @Test
    public void initNeProof() {

        CredentialPrimaryPublicKey pk = issuer.getCredentialPrimaryPublicKey();
        PrimaryEqualInitProof init_eq_proof = prover.getPrimaryEqInitProof();
        Predicate predicate = prover.predicate();
        CredentialValues credential_values = issuer.getCredentialValues();

        PrimaryPredicateInequalityInitProof init_ne_proof = PrimaryPredicateInequalityProof.init(
                pk,
                init_eq_proof.m_tilde,
                credential_values,
                predicate);

        assertEquals(prover.getPrimaryNeInitProof(), init_ne_proof);
    }

    @Test
    public void  initPrimaryProof() throws CryptoException {

        CredentialPrimaryPublicKey pk = issuer.getCredentialPrimaryPublicKey();
        CredentialSchema credential_schema = issuer.getCredentialSchema();
        NonCredentialSchema non_credential_schema = issuer.getNonCredentialSchema();
        CredentialSignature credential = prover.getCredentialSignature();
        CredentialValues credential_values = issuer.getCredentialValues();
        SubProofRequest sub_proof_request = prover.getSubProofRequest();
        Map<String, BigInteger> common_attributes = prover.getProofCommonAttributes();
        BigInteger m2_tilde = new BigInteger(1, prover.getNonRevocationInitProof().tau_list_params.m2.toBytes());

        PrimaryInitProof init_proof = PrimaryProof.init(
                common_attributes,
                pk,
                credential.p_credential,
                credential_values,
                credential_schema,
                non_credential_schema,
                sub_proof_request,
                m2_tilde);

        assertEquals(prover.getPrimaryInitProof(), init_proof);
    }

    @Test
    public void finalizeEqProof() {

        BigInteger c_hash = prover.getAggregatedProof().c_hash;
        PrimaryEqualInitProof init_proof = prover.getPrimaryEqInitProof();
        CredentialValues credential_values = issuer.getCredentialValues();
        NonCredentialSchema non_credential_schema = issuer.getNonCredentialSchema();
        CredentialSchema credential_schema = issuer.getCredentialSchema();
        SubProofRequest sub_proof_request = prover.getSubProofRequest();

        PrimaryEqualProof eq_proof = PrimaryEqualProof.finalize(
                init_proof,
                c_hash,
                credential_schema,
                non_credential_schema,
                credential_values,
                sub_proof_request);
        assertEquals(prover.getPrimaryEqProof(), eq_proof);
    }

    @Test
    public void finalizeNeProof() {

        BigInteger c_h = prover.getAggregatedProof().c_hash;
        PrimaryPredicateInequalityInitProof ne_proof = prover.getPrimaryNeInitProof();
        PrimaryEqualProof eq_proof = prover.getPrimaryEqProof();

        PrimaryPredicateInequalityProof neProof = PrimaryPredicateInequalityProof.finalize(c_h, ne_proof, eq_proof);
        assertEquals(prover.getPrimaryPredicateNeProof(), neProof);
    }

    @Test
    public void finalizePrimaryProof() {

        PrimaryInitProof proof = prover.getPrimaryInitProof();
        BigInteger c_h = prover.getAggregatedProof().c_hash;
        CredentialSchema credential_schema = issuer.getCredentialSchema();
        NonCredentialSchema non_credential_schema = issuer.getNonCredentialSchema();;
        CredentialValues credential_values = issuer.getCredentialValues();
        SubProofRequest sub_proof_request = prover.getSubProofRequest();

        PrimaryProof primaryProof = PrimaryProof.finalize(
                proof,
                c_h,
                credential_schema,
                non_credential_schema,
                credential_values,
                sub_proof_request);


        assertEquals(prover.getPrimaryProof(), primaryProof);
    }
}