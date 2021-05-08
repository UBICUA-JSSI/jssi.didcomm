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

package jssi.ursa.credential.zerokp;

import jssi.ursa.credential.*;
import jssi.ursa.credential.issuer.Issuer;
import jssi.ursa.credential.proof.Proof;
import jssi.ursa.credential.proof.ProofBuilder;
import jssi.ursa.credential.proof.SubProofRequest;
import jssi.ursa.credential.prover.MasterSecret;
import jssi.ursa.credential.prover.Prover;
import jssi.ursa.credential.util.BigNumber;
import jssi.ursa.credential.verifier.ProofVerifier;
import jssi.ursa.credential.verifier.Verifier;
import jssi.ursa.pair.CryptoException;
import jssi.ursa.registry.RevocationRegistryDefinition;
import jssi.ursa.registry.SimpleTailsAccessor;
import jssi.ursa.registry.Witness;
import org.junit.jupiter.api.Test;


import java.math.BigInteger;

import static jssi.ursa.credential.util.BigNumber.LARGE_NONCE;
import static jssi.ursa.credential.zerokp.ZeroKP.LINK_SECRET;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;


public class ZeroKP_RevocationProof_BeforeRevoked {

    @Test
    public void verify() throws CryptoException {

        // 1. Issuer creates credential schema
        CredentialSchema credential_schema = ZeroKP.gvtCredentialSchema();
        NonCredentialSchema non_credential_schema = ZeroKP.nonCredentialSchema();

        // 2. Issuer creates credential definition(with revocation keys)
        CredentialDefinition credentialDefinition = Issuer.createCredentialDefinition(
                credential_schema,
                non_credential_schema,
                true);

        // 3. Issuer creates revocation registry with Issuance on demand type
        int max_cred_num = 5;
        boolean issuance_by_default = false;
        RevocationRegistryDefinition revocationRegistryDefinition = Issuer.createRevocationRegistryDefinition(
                credentialDefinition.getCredentialPublicKey(),
                max_cred_num,
                issuance_by_default);

        SimpleTailsAccessor simple_tail_accessor = SimpleTailsAccessor.create(revocationRegistryDefinition.getRevocationTailsGenerator());

        // 4. Issuer creates master secret and sign credential values
        CredentialValues credential_values = ZeroKP.gvtCredentialValues(MasterSecret.create());

        // 5. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
        BigInteger credential_nonce = ZeroKP.getCredentialNonce();

        // 6. Prover blinds hidden attributes
        BlindedCredentials blindedCredentials = Prover.blindCredentialSecrets(
                credentialDefinition.getCredentialPublicKey(),
                credentialDefinition.getCredentialKeyCorrectnessProof(),
                credential_values,
                credential_nonce);

        // 7. Prover creates nonce used by Issuer to create correctness proof for signature
        BigInteger credential_issuance_nonce = ZeroKP.getCredentialIssuanceNonce();

        int rev_idx = 1;

        SignedCredential signedCredential = Issuer.signCredentialWithRevocation(
                ZeroKP.PROVER_DID,
                blindedCredentials.getBlindedCredentialSecrets(),
                blindedCredentials.getBlindedCredentialSecretsCorrectnessProof(),
                credential_nonce,
                credential_issuance_nonce,
                credential_values,
                credentialDefinition.getCredentialPublicKey(),
                credentialDefinition.getCredentialPrivateKey(),
                rev_idx,
                max_cred_num,
                issuance_by_default,
                revocationRegistryDefinition.getRevocationRegistry(),
                revocationRegistryDefinition.getRevocationPrivateKey(),
                simple_tail_accessor);

        // 8. Prover creates witness
        Witness witness = Witness.create(
                rev_idx,
                max_cred_num,
                issuance_by_default,
                signedCredential.revocationRegistryDelta,
                simple_tail_accessor);


        // 9. Prover processes credential signature
        Prover.processCredentialSignature(
                signedCredential.credentialSignature,
                credential_values,
                signedCredential.signatureCorrectnessProof,
                blindedCredentials.getCredentialSecretsBlindingFactors(),
                credentialDefinition.getCredentialPublicKey(),
                credential_issuance_nonce,
                revocationRegistryDefinition.getRevocationPublicKey(),
                revocationRegistryDefinition.getRevocationRegistry(),
                witness);

        // 10. Verifier creates nonce
        BigInteger nonce = BigNumber.random(LARGE_NONCE);

        // 11. Verifier create sub proof request
        SubProofRequest sub_proof_request = ZeroKP.gvtSubProofRequest();

        // 12. Prover creates proof
        ProofBuilder proof_builder = new ProofBuilder();
        proof_builder.addCommonAttr(LINK_SECRET);
        proof_builder.addSubProofRequest(
                sub_proof_request,
                credential_schema,
                non_credential_schema,
                signedCredential.credentialSignature,
                credential_values,
                credentialDefinition.getCredentialPublicKey(),
                revocationRegistryDefinition.getRevocationRegistry(),
                witness);
        Proof proof = proof_builder.build(nonce);

        // 13. Verifier verifies proof
        ProofVerifier proof_verifier = Verifier.createProofVerifier();
        proof_verifier.addSubProofRequest(
                sub_proof_request,
                credential_schema,
                non_credential_schema,
                credentialDefinition.getCredentialPublicKey(),
                revocationRegistryDefinition.getRevocationPublicKey(),
                revocationRegistryDefinition.getRevocationRegistry());

        assertTrue(proof_verifier.verify(proof, nonce));

        // 14. Issuer revokes credential used for proof building
        Issuer.revokeCredential(
                revocationRegistryDefinition.getRevocationRegistry(),
                max_cred_num,
                rev_idx,
                simple_tail_accessor);

        // 15. Verifier verifies proof
        proof_verifier = Verifier.createProofVerifier();
        proof_verifier.addSubProofRequest(
                sub_proof_request,
                credential_schema,
                non_credential_schema,
                credentialDefinition.getCredentialPublicKey(),
                revocationRegistryDefinition.getRevocationPublicKey(),
                revocationRegistryDefinition.getRevocationRegistry());

        assertFalse(proof_verifier.verify(proof, nonce));
    }
}
