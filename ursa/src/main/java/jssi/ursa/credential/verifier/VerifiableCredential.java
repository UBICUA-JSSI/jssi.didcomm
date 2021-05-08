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

package jssi.ursa.credential.verifier;

import jssi.ursa.credential.CredentialSchema;
import jssi.ursa.credential.NonCredentialSchema;
import jssi.ursa.credential.CredentialPublicKey;
import jssi.ursa.credential.proof.SubProofRequest;
import jssi.ursa.registry.RevocationPublicKey;
import jssi.ursa.registry.RevocationRegistry;

public class VerifiableCredential {
    CredentialPublicKey pub_key;
    SubProofRequest sub_proof_request;
    CredentialSchema credential_schema;
    NonCredentialSchema non_credential_schema;
    RevocationPublicKey rev_key_pub;
    RevocationRegistry rev_reg;

    public VerifiableCredential(
            CredentialPublicKey pub_key,
            SubProofRequest sub_proof_request,
            CredentialSchema credential_schema,
            NonCredentialSchema non_credential_schema,
            RevocationPublicKey rev_key_pub,
            RevocationRegistry rev_reg)
    {
        this.pub_key = pub_key;
        this.sub_proof_request = sub_proof_request;
        this.credential_schema = credential_schema;
        this.non_credential_schema = non_credential_schema;
        this.rev_key_pub = rev_key_pub;
        this.rev_reg = rev_reg;
    }
}
