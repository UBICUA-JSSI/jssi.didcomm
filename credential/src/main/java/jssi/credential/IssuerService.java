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

package jssi.credential;

import jssi.ursa.credential.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import jssi.credential.credential.CredentialDefinitionData;
import jssi.credential.request.CredentialRequest;
import jssi.credential.revocation.RevocationRegistryDefinitionValuePublicKeys;
import jssi.credential.schema.AttributeNames;
import jssi.credential.did.Did;

import jssi.ursa.credential.issuer.Issuer;
import jssi.ursa.pair.CryptoException;
import jssi.ursa.registry.*;

import java.math.BigInteger;

public class IssuerService {

    private static final Logger LOG = LoggerFactory.getLogger(IssuerService.class);

    public IssuerService(){}

    public IssuerCredentialDefinition createCredentialDefinition(AttributeNames attributeNames, boolean isRevocable){

        CredentialSchema credentialSchema = CredentialHelper.buildCredentialSchema(attributeNames);
        NonCredentialSchema nonCredentialSchema = CredentialHelper.buildNonCredentialSchema();
        CredentialDefinition credentialDefinition = Issuer.createCredentialDefinition(credentialSchema, nonCredentialSchema, isRevocable);

        CredentialDefinitionData credentialDefinitionData = new CredentialDefinitionData(
                credentialDefinition.getCredentialPublicKey().p_key,
                credentialDefinition.getCredentialPublicKey().r_key);
        return new IssuerCredentialDefinition(
                credentialDefinitionData,
                credentialDefinition.getCredentialPrivateKey(),
                credentialDefinition.getCredentialKeyCorrectnessProof());
    }

    public IssuerRevocationRegistry createRevocationRegistry(
            jssi.credential.credential.CredentialDefinition credentialDefinition,
            int maxCredentials,
            boolean isDefault,
            Did did) throws CryptoException {

        CredentialPublicKey credentialPublicKey = new CredentialPublicKey(
                credentialDefinition.value.primary,
                credentialDefinition.value.revocation);

        RevocationRegistryDefinition revocationRegistryDefinition = Issuer.createRevocationRegistryDefinition(
                credentialPublicKey,
                maxCredentials,
                isDefault);

        RevocationRegistryDefinitionValuePublicKeys revocationRegistryDefinitionValuePublicKeys = new RevocationRegistryDefinitionValuePublicKeys(
                revocationRegistryDefinition.getRevocationPublicKey());

        return new IssuerRevocationRegistry(
                revocationRegistryDefinitionValuePublicKeys,
                revocationRegistryDefinition.getRevocationPrivateKey(),
                revocationRegistryDefinition.getRevocationRegistry(),
                revocationRegistryDefinition.getRevocationTailsGenerator());
    }

    public SignedCredential createCredential(
            jssi.credential.credential.CredentialDefinition credentialDefinition,
            CredentialPrivateKey credentialPrivateKey,
            BigInteger cred_issuance_blinding_nonce,
            CredentialRequest credentialRequest,
            jssi.credential.credential.CredentialValues credentialValues,
            Integer rev_idx,
            jssi.credential.revocation.RevocationRegistryDefinition revocationRegistryDefinition,
            RevocationRegistry revocationRegistry,
            RevocationPrivateKey revocationPrivateKey,
            RevocationTailsAccessor revocationTailsAccessor) throws InvalidStateException, CryptoException {

        CredentialValues credential_values = CredentialHelper.buildCredentialValues(credentialValues, null);

        CredentialPublicKey credentialPublicKey = new CredentialPublicKey(
                credentialDefinition.value.primary,
                credentialDefinition.value.revocation);

        if(rev_idx != null){
            if(revocationRegistry == null) {
                throw new InvalidStateException("RevocationRegistry not found");
            } else if(revocationPrivateKey == null) {
                throw new InvalidStateException("RevocationPrivateKey not found");
            } else if(revocationRegistryDefinition == null) {
                throw new InvalidStateException("RevocationRegistryDefinitionValue not found");
            } else if(revocationTailsAccessor == null) {
                throw new InvalidStateException("RevocationTailsAccessor not found");
            }

            return Issuer.signCredentialWithRevocation(
                    credentialRequest.prover_did.did,
                    credentialRequest.blinded_ms,
                    credentialRequest.blinded_ms_correctness_proof,
                    cred_issuance_blinding_nonce,
                    credentialRequest.nonce,
                    credential_values,
                    credentialPublicKey,
                    credentialPrivateKey,
                    rev_idx,
                    revocationRegistryDefinition.value.max_cred_num,
                    revocationRegistryDefinition.value.issuance_type.isDefault(),
                    revocationRegistry,
                    revocationPrivateKey,
                    revocationTailsAccessor);

        } else{
            return Issuer.signCredential(
                    credentialRequest.prover_did.did,
                    credentialRequest.blinded_ms,
                    credentialRequest.blinded_ms_correctness_proof,
                    cred_issuance_blinding_nonce,
                    credentialRequest.nonce,
                    credential_values,
                    credentialPublicKey,
                    credentialPrivateKey);
        }
    }

    public RevocationRegistryDelta revoke (
            RevocationRegistry revocationRegistry,
            int maxCredentials,
            int rev_idx,
            RevocationTailsAccessor revocationTailsAccessor) {

        return Issuer.revokeCredential(revocationRegistry, maxCredentials, rev_idx, revocationTailsAccessor);
    }

    public RevocationRegistryDelta restore (
            RevocationRegistry revocationRegistry,
            int maxCredentials,
            int rev_idx,
            RevocationTailsAccessor revocationTailsAccessor) {

        return Issuer.restoreCredential(revocationRegistry, maxCredentials, rev_idx, revocationTailsAccessor);
    }

}
