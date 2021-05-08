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
import static org.junit.jupiter.api.Assertions.assertTrue;


public class ZeroKP_RevocationProof_TwoCredentials {

    @Test
    public void verify() throws CryptoException {

        // 1. Prover creates master secret
        MasterSecret masterSecret = MasterSecret.create();

        // Issuer creates GVT credential
        // 2. Issuer creates GVT credential schema
        CredentialSchema gvtCredentialSchema = ZeroKP.gvtCredentialSchema();
        NonCredentialSchema gvtNonCredentialSchema = ZeroKP.nonCredentialSchema();

        // 3. Issuer creates GVT credential definition(with revocation keys)
        CredentialDefinition gvtCredentialDefinition = Issuer.createCredentialDefinition(
                gvtCredentialSchema,
                gvtNonCredentialSchema,
                true);

        // 4. Issuer creates GVT revocation registry with Issuance on demand type
        int gvtMaxCredentials = 5;
        boolean gvtIsDefault = false;
        RevocationRegistryDefinition gvtRevocationRegistryDefinition = Issuer.createRevocationRegistryDefinition(
                gvtCredentialDefinition.getCredentialPublicKey(),
                gvtMaxCredentials,
                gvtIsDefault);

        SimpleTailsAccessor gvtTailAccessor = SimpleTailsAccessor.create(gvtRevocationRegistryDefinition.getRevocationTailsGenerator());

        // 5. Issuer creates and sign credential values
        CredentialValues gvtCredentialValues = ZeroKP.gvtCredentialValues(MasterSecret.create());

        // 6. Issuer creates GVT nonce used by Prover to create correctness proof for blinded secrets
        BigInteger gvtCredentialNonce = ZeroKP.getCredentialNonce();

        // 7. Prover blinds GVT hidden attributes
        BlindedCredentials gvtBlindedCredentials = Prover.blindCredentialSecrets(
                gvtCredentialDefinition.getCredentialPublicKey(),
                gvtCredentialDefinition.getCredentialKeyCorrectnessProof(),
                gvtCredentialValues,
                gvtCredentialNonce);

        // 8. Prover creates GVT nonce used by Issuer to create correctness proof for signature
        BigInteger gvtCredentialIssuanceNonce = ZeroKP.getCredentialIssuanceNonce();

        // 9. Issuer signs GVT credential values
        int gvtRevocationIdx = 1;
        SignedCredential gvtSignedCredential = Issuer.signCredentialWithRevocation(
                ZeroKP.PROVER_DID,
                gvtBlindedCredentials.getBlindedCredentialSecrets(),
                gvtBlindedCredentials.getBlindedCredentialSecretsCorrectnessProof(),
                gvtCredentialNonce,
                gvtCredentialIssuanceNonce,
                gvtCredentialValues,
                gvtCredentialDefinition.getCredentialPublicKey(),
                gvtCredentialDefinition.getCredentialPrivateKey(),
                gvtRevocationIdx,
                gvtMaxCredentials,
                gvtIsDefault,
                gvtRevocationRegistryDefinition.getRevocationRegistry(),
                gvtRevocationRegistryDefinition.getRevocationPrivateKey(),
                gvtTailAccessor);

        // 10. Prover creates GVT witness
        Witness gvtWitness = Witness.create(
                gvtRevocationIdx,
                gvtMaxCredentials,
                gvtIsDefault,
                gvtSignedCredential.revocationRegistryDelta,
                gvtTailAccessor);


        // 11. Prover processes GVT credential signature
        Prover.processCredentialSignature(
                gvtSignedCredential.credentialSignature,
                gvtCredentialValues,
                gvtSignedCredential.signatureCorrectnessProof,
                gvtBlindedCredentials.getCredentialSecretsBlindingFactors(),
                gvtCredentialDefinition.getCredentialPublicKey(),
                gvtCredentialIssuanceNonce,
                gvtRevocationRegistryDefinition.getRevocationPublicKey(),
                gvtRevocationRegistryDefinition.getRevocationRegistry(),
                gvtWitness);

        // Issuer creates XYZ credential
        // 12. Issuer creates XYZ credential schema
        CredentialSchema xyzCredentialSchema = ZeroKP.xyzCredentialSchema();
        NonCredentialSchema xyzNonCredentialSchema = ZeroKP.nonCredentialSchema();

        // 13. Issuer creates XYZ credential definition (with revocation keys)
        CredentialDefinition xyzCredentialDefinition = Issuer.createCredentialDefinition(
                xyzCredentialSchema,
                xyzNonCredentialSchema,
                true);

        // 14. Issuer creates XYZ revocation registry with IssuanceByDefault type
        int xyzMaxCredentials = 5;
        boolean xyzIsDefault = false;
        RevocationRegistryDefinition xyzRevocationRegistryDefinition = Issuer.createRevocationRegistryDefinition(
                xyzCredentialDefinition.getCredentialPublicKey(),
                xyzMaxCredentials,
                xyzIsDefault);

        SimpleTailsAccessor xyzTailAccessor = SimpleTailsAccessor.create(xyzRevocationRegistryDefinition.getRevocationTailsGenerator());

        // 15. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
        BigInteger xyzCredentialNonce = ZeroKP.getCredentialNonce();

        // 16. Issuer creates XYZ credential values
        CredentialValues xyzCredentialValues = ZeroKP.xyzCredentialValues(MasterSecret.create());

        // 17. Prover blinds XYZ hidden attributes
        BlindedCredentials xyzBlindedCredentials = Prover.blindCredentialSecrets(
                xyzCredentialDefinition.getCredentialPublicKey(),
                xyzCredentialDefinition.getCredentialKeyCorrectnessProof(),
                xyzCredentialValues,
                xyzCredentialNonce);

        // 18. Prover creates nonce used by Issuer to create correctness proof for XYZ signature
        BigInteger xyzCredentialIssuanceNonce = ZeroKP.getCredentialIssuanceNonce();

        // 19. Issuer signs XYZ credential values
        int xyzRevocationIdx = 1;
        SignedCredential xyzSignedCredential = Issuer.signCredentialWithRevocation(
                ZeroKP.PROVER_DID,
                xyzBlindedCredentials.getBlindedCredentialSecrets(),
                xyzBlindedCredentials.getBlindedCredentialSecretsCorrectnessProof(),
                xyzCredentialNonce,
                xyzCredentialIssuanceNonce,
                xyzCredentialValues,
                xyzCredentialDefinition.getCredentialPublicKey(),
                xyzCredentialDefinition.getCredentialPrivateKey(),
                xyzRevocationIdx,
                xyzMaxCredentials,
                xyzIsDefault,
                xyzRevocationRegistryDefinition.getRevocationRegistry(),
                xyzRevocationRegistryDefinition.getRevocationPrivateKey(),
                xyzTailAccessor);

        // 20. Prover creates XYZ witness
        Witness xyzWitness = Witness.create(
                xyzRevocationIdx,
                xyzMaxCredentials,
                xyzIsDefault,
                xyzSignedCredential.revocationRegistryDelta,
                xyzTailAccessor);

        // 21. Prover processes XYZ credential signature
        Prover.processCredentialSignature(
                xyzSignedCredential.credentialSignature,
                xyzCredentialValues,
                xyzSignedCredential.signatureCorrectnessProof,
                xyzBlindedCredentials.getCredentialSecretsBlindingFactors(),
                xyzCredentialDefinition.getCredentialPublicKey(),
                xyzCredentialIssuanceNonce,
                xyzRevocationRegistryDefinition.getRevocationPublicKey(),
                xyzRevocationRegistryDefinition.getRevocationRegistry(),
                xyzWitness);

        // 22. Verifier creates sub proof request related to GVT credential
        SubProofRequest gvtSubProofRequest = ZeroKP.gvtSubProofRequest();

        // 23. Verifier creates sub proof request related to XYZ credential
        SubProofRequest xyzSubProofRequest = ZeroKP.xyzSubProofRequest();

        // 24. Verifier creates nonce
        BigInteger nonce = BigNumber.random(LARGE_NONCE);

        // 25. Prover creates proof for two sub proof requests
        ProofBuilder proofBuilder = new ProofBuilder();
        proofBuilder.addCommonAttr(LINK_SECRET);
        proofBuilder.addSubProofRequest(
                gvtSubProofRequest,
                gvtCredentialSchema,
                gvtNonCredentialSchema,
                gvtSignedCredential.credentialSignature,
                gvtCredentialValues,
                gvtCredentialDefinition.getCredentialPublicKey(),
                gvtRevocationRegistryDefinition.getRevocationRegistry(),
                gvtWitness);

        proofBuilder.addSubProofRequest(
                xyzSubProofRequest,
                xyzCredentialSchema,
                xyzNonCredentialSchema,
                xyzSignedCredential.credentialSignature,
                xyzCredentialValues,
                xyzCredentialDefinition.getCredentialPublicKey(),
                xyzRevocationRegistryDefinition.getRevocationRegistry(),
                xyzWitness);

        Proof proof = proofBuilder.build(nonce);

        // 26. Verifier verifies proof
        ProofVerifier proofVerifier = Verifier.createProofVerifier();
        proofVerifier.addSubProofRequest(
                gvtSubProofRequest,
                gvtCredentialSchema,
                gvtNonCredentialSchema,
                gvtCredentialDefinition.getCredentialPublicKey(),
                gvtRevocationRegistryDefinition.getRevocationPublicKey(),
                gvtRevocationRegistryDefinition.getRevocationRegistry());

        proofVerifier.addSubProofRequest(
                xyzSubProofRequest,
                xyzCredentialSchema,
                xyzNonCredentialSchema,
                xyzCredentialDefinition.getCredentialPublicKey(),
                xyzRevocationRegistryDefinition.getRevocationPublicKey(),
                xyzRevocationRegistryDefinition.getRevocationRegistry());

        assertTrue(proofVerifier.verify(proof, nonce));
    }
}
