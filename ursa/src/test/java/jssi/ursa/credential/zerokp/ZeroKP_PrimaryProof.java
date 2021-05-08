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

import org.junit.jupiter.api.Test;
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

import java.math.BigInteger;

import static jssi.ursa.credential.util.BigNumber.LARGE_NONCE;
import static jssi.ursa.credential.zerokp.ZeroKP.LINK_SECRET;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ZeroKP_PrimaryProof {

    @Test
    public void verify() throws CryptoException {

        // 1. Issuer creates credential schema
        CredentialSchema credentialSchema = ZeroKP.gvtCredentialSchema();
        NonCredentialSchema nonCredentialSchema = ZeroKP.nonCredentialSchema();

        // 2. Issuer creates credential definition
        CredentialDefinition credentialDefinition = Issuer.createCredentialDefinition(
                credentialSchema,
                nonCredentialSchema,
                false);

        // 3. Issuer creates credential values
        CredentialValues credentialValues = ZeroKP.gvtCredentialValues(MasterSecret.create());

        // 4. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
        BigInteger credentialNonce = ZeroKP.getCredentialNonce();

        // 5. Prover blinds hidden attributes
        BlindedCredentials blindedCredentials = Prover.blindCredentialSecrets(
                credentialDefinition.getCredentialPublicKey(),
                credentialDefinition.getCredentialKeyCorrectnessProof(),
                credentialValues,
                credentialNonce);

        // 6. Prover creates nonce used by Issuer to create correctness proof for signature
        BigInteger credentialIssuanceNonce = ZeroKP.getCredentialIssuanceNonce();

        // 7. Issuer signs credential values
        SignedCredential signedCredential = Issuer.signCredential(
                ZeroKP.PROVER_DID,
                blindedCredentials.getBlindedCredentialSecrets(),
                blindedCredentials.getBlindedCredentialSecretsCorrectnessProof(),
                credentialNonce,
                credentialIssuanceNonce,
                credentialValues,
                credentialDefinition.getCredentialPublicKey(),
                credentialDefinition.getCredentialPrivateKey());

        // 8. Prover processes credential signature
        Prover.processCredentialSignature(
                signedCredential.credentialSignature,
                credentialValues,
                signedCredential.signatureCorrectnessProof,
                blindedCredentials.getCredentialSecretsBlindingFactors(),
                credentialDefinition.getCredentialPublicKey(),
                credentialIssuanceNonce,
                null,
                null,
                null);

        // 9. Verifier create sub proof request
        SubProofRequest subProofRequest = ZeroKP.gvtSubProofRequest();

        // 10. Verifier creates nonce
        BigInteger nonce = BigNumber.random(LARGE_NONCE);

        // 11. Prover creates proof
        ProofBuilder proofBuilder = new ProofBuilder();
        proofBuilder.addCommonAttr(LINK_SECRET);
        proofBuilder.addSubProofRequest(
                subProofRequest,
                credentialSchema,
                nonCredentialSchema,
                signedCredential.credentialSignature,
                credentialValues,
                credentialDefinition.getCredentialPublicKey(),
                null,
                null);
        Proof proof = proofBuilder.build(nonce);

        // 12. Verifier verifies proof
        ProofVerifier proofVerifier = Verifier.createProofVerifier();
        proofVerifier.addSubProofRequest(
                subProofRequest,
                credentialSchema,
                nonCredentialSchema,
                credentialDefinition.getCredentialPublicKey(),
                null,
                null);

        assertTrue(proofVerifier.verify(proof, nonce));
    }
}
