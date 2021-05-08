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

import jssi.credential.credential.CredentialDefinitionId;
import jssi.credential.did.Did;
import jssi.ursa.credential.BlindedCredentialSecrets;
import jssi.ursa.credential.BlindedCredentialSecretsCorrectnessProof;

import java.math.BigInteger;

public class CredentialRequest {

    public Did prover_did;
    public CredentialDefinitionId cred_def_id;
    public BlindedCredentialSecrets blinded_ms;
    public BlindedCredentialSecretsCorrectnessProof blinded_ms_correctness_proof;
    public BigInteger nonce;

    public CredentialRequest(
            Did prover_did,
            CredentialDefinitionId cred_def_id,
            BlindedCredentialSecrets blinded_ms,
            BlindedCredentialSecretsCorrectnessProof blinded_ms_correctness_proof,
            BigInteger nonce)
    {
        this.prover_did = prover_did;
        this.cred_def_id = cred_def_id;
        this.blinded_ms = blinded_ms;
        this.blinded_ms_correctness_proof = blinded_ms_correctness_proof;
    }
}
