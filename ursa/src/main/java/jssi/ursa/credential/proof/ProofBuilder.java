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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import jssi.ursa.credential.*;
import jssi.ursa.credential.util.BigNumber;
import jssi.ursa.pair.CryptoException;
import jssi.ursa.registry.RevocationRegistry;
import jssi.ursa.registry.Witness;

import java.math.BigInteger;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static jssi.ursa.util.BigIntegers.asUnsignedByteArray;
import static jssi.ursa.credential.util.BigNumber.LARGE_MVECT;

public class ProofBuilder {

    private static final Logger LOG = LoggerFactory.getLogger(ProofBuilder.class);

    private Map<String, BigInteger> common_attributes = new HashMap<>();
    private List<InitProof> init_proofs = new ArrayList<>();
    private List<byte[]> c_list = new ArrayList<>();
    private List<byte[]> tau_list = new ArrayList<>();

    public ProofBuilder(){}

    /**
     * Creates m_tildes for attributes that will be the same across all subproofs
     *
     * @param attr_name
     */
    public void addCommonAttr(String attr_name)  {
        common_attributes.put(attr_name, BigNumber.random(LARGE_MVECT));
    }

    /**
     *
     * @param subProofRequest
     * @param credentialSchema
     * @param nonCredentialSchema
     * @param credentialSignature
     * @param credentialValues
     * @param credentialPublicKey
     * @param revocationRegistry
     * @param witness
     * @throws CryptoException
     *
     * Adds sub proof request to proof builder which will be used fo building of proof.
     * Part of proof request related to a particular schema-key.
     * The order of sub-proofs is important: both Prover and Verifier should use the same order.
     *
     * Example
     *
     * CredentialSchemaBuilder builder = CredentialSchema.CredentialSchemaBuilder().builder();
     * builder.addAttr("sex");
     * CredentialSchema credentialSchema = builder.build();
     *
     * NonCredentialSchemaBuilder nonBuilder = NonCredentialSchema.NonCredentialSchemaBuilder.builder();
     * nonBuilder.addAttr("master_secret");
     * NonCredentialSchema nonCredentialSchema = nonBuilder.build();
     *
     * CredentialDefinition credentialDefinition = Issuer.createCredentialDefinition(credentialSchema, nonCredentialSchema, false);
     *
     * MasterSecret masterSecret = MasterSecret.create();
     *
     * CredentialValues.CredentialValuesBuilder credentialValuesBuilder = CredentialValues.builder();
     * credentialValuesBuilder.addHidden("master_secret", masterSecret.ms);
     * credentialValuesBuilder.addKnown("name", "5944657099558967239210949258394887428692050081607692519917050011144233115103");
     * CredentialValues credentialValues = credentialValuesBuilder.build();
     *
     * BigInteger credentialNonce = BigNumber.random(LARGE_NONCE);
     * BlindedCredentials blindedCredentials = Prover.blindCredentialSecrets(
     *                credentialDefinition.getCredentialPublicKey(),
     *                credentialDefinition.getCredentialKeyCorrectnessProof(),
     *                credentialValues,
     *                credentialNonce);
     * BigInteger issuanceNonce = BigNumber.random(LARGE_NONCE);
     *
     * SignedCredential signedCredential = Issuer.signCredential(
     *                   "CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
     *                   blindedCredentials.getBlindedCredentialSecrets(),
     *                   blindedCredentials.getBlindedCredentialSecretsCorrectnessProof(),
     *                   credentialNonce,
     *                   issuanceNonce,
     *                   credentialValues,
     *                   credentialDefinition.getCredentialPublicKey(),
     *                   credentialDefinition.getCredentialPrivateKey());
     *
     * boolean result = Prover.processCredentialSignature(signedCredential.credentialSignature,
     *                   credentialValues,
     *                   signedCredential.signatureCorrectnessProof,
     *                   blindedCredentials.credentialSecretsBlindingFactors,
     *                   credentialDefinition.getCredentialPublicKey(),
     *                   issuanceNonce,
     *                   null, null, ull);
     *
     * SubProofRequest.SubProofRequestBuilder  subProofRequestBuilder = SubProofRequest.builder();
     * subProofRequestBuilder.addRevealedAttr("sex").unwrap();
     * SubProofRequest subProofRequest = subProofRequestBuilder.build();
     *
     * ProofBuilder proofBuilder = new ProofBuilder();
     * proofBuilder.addCommonAttr("master_secret").unwrap();
     * proofBuilder.addSubProofRequest(subProofRequest,
     *                                  credentialSchema,
     *                                  nonCredentialSchema,
     *                                  signedCredential.credentialSignature,
     *                                  credentialValues,
     *                                  credentialDefinition.getCredentialPublicKey(),
     *                                  null,
     *                                  null);
     *
     */
    public void addSubProofRequest(
            SubProofRequest subProofRequest,
            CredentialSchema credentialSchema,
            NonCredentialSchema nonCredentialSchema,
            CredentialSignature credentialSignature,
            CredentialValues credentialValues,
            CredentialPublicKey credentialPublicKey,
            RevocationRegistry revocationRegistry,
            Witness witness) throws CryptoException {

        if(!checkAddSubProofRequestParamsConsistency(
                credentialValues,
                subProofRequest,
                credentialSchema,
                nonCredentialSchema)){
            return;
        }

        NonRevocInitProof nonRevocInitProof = null;
        BigInteger m2_tilde = null;

        if(credentialSignature.r_credential != null && revocationRegistry != null && credentialPublicKey.r_key != null && witness != null)
        {
            NonRevocInitProof proof = NonRevocProof.init(
                    credentialSignature.r_credential,
                    revocationRegistry,
                    credentialPublicKey.r_key,
                    witness);

            c_list.addAll(proof.toCList());
            tau_list.addAll(proof.toTauList());
            m2_tilde = new BigInteger(1, proof.tau_list_params.m2.toBytes());
            nonRevocInitProof = proof;
        }

        PrimaryInitProof primaryInitProof = PrimaryProof.init(
                common_attributes,
                credentialPublicKey.p_key,
                credentialSignature.p_credential,
                credentialValues,
                credentialSchema,
                nonCredentialSchema,
                subProofRequest,
                m2_tilde);

        c_list.addAll(primaryInitProof.toCList());
        tau_list.addAll(primaryInitProof.toTauList());

        InitProof initProof = new InitProof(
                primaryInitProof,
                nonRevocInitProof,
                credentialValues,
                subProofRequest,
                credentialSchema,
                nonCredentialSchema);

        init_proofs.add(initProof);
    }

    /**
     *
     * @param nonce
     * @return Proof
     * @throws CryptoException
     *
     * Build proof
     *
     *
     * Example
     *
     * CredentialSchemaBuilder builder = CredentialSchema.CredentialSchemaBuilder().builder();
     * builder.addAttr("sex");
     * CredentialSchema credentialSchema = builder.build();
     *
     * NonCredentialSchemaBuilder nonBuilder = NonCredentialSchema.NonCredentialSchemaBuilder.builder();
     * nonBuilder.addAttr("master_secret");
     * NonCredentialSchema nonCredentialSchema = nonBuilder.build();
     *
     * CredentialDefinition credentialDefinition = Issuer.createCredentialDefinition(credentialSchema, nonCredentialSchema, false);
     *
     * MasterSecret masterSecret = MasterSecret.create();
     *
     * CredentialValues.CredentialValuesBuilder credentialValuesBuilder = CredentialValues.builder();
     * credentialValuesBuilder.addHidden("master_secret", masterSecret.ms);
     * credentialValuesBuilder.addKnown("name", "5944657099558967239210949258394887428692050081607692519917050011144233115103");
     * CredentialValues credentialValues = credentialValuesBuilder.build();
     *
     * BigInteger credentialNonce = BigNumber.random(LARGE_NONCE);
     * BlindedCredentials blindedCredentials = Prover.blindCredentialSecrets(
     *                credentialDefinition.getCredentialPublicKey(),
     *                credentialDefinition.getCredentialKeyCorrectnessProof(),
     *                credentialValues,
     *                credentialNonce);
     * BigInteger issuanceNonce = BigNumber.random(LARGE_NONCE);
     *
     * SignedCredential signedCredential = Issuer.signCredential(
     *                   "CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
     *                   blindedCredentials.getBlindedCredentialSecrets(),
     *                   blindedCredentials.getBlindedCredentialSecretsCorrectnessProof(),
     *                   credentialNonce,
     *                   issuanceNonce,
     *                   credentialValues,
     *                   credentialDefinition.getCredentialPublicKey(),
     *                   credentialDefinition.getCredentialPrivateKey());
     *
     * boolean result = Prover.processCredentialSignature(signedCredential.credentialSignature,
     *                   credentialValues,
     *                   signedCredential.signatureCorrectnessProof,
     *                   blindedCredentials.credentialSecretsBlindingFactors,
     *                   credentialDefinition.getCredentialPublicKey(),
     *                   issuanceNonce,
     *                   null, null, ull);
     *
     * SubProofRequest.SubProofRequestBuilder  subProofRequestBuilder = SubProofRequest.builder();
     * subProofRequestBuilder.addRevealedAttr("sex").unwrap();
     * SubProofRequest subProofRequest = subProofRequestBuilder.build();
     *
     * ProofBuilder proofBuilder = new ProofBuilder();
     * proofBuilder.addCommonAttr("master_secret").unwrap();
     * proofBuilder.addSubProofRequest(subProofRequest,
     *                                  credentialSchema,
     *                                  nonCredentialSchema,
     *                                  signedCredential.credentialSignature,
     *                                  credentialValues,
     *                                  credentialDefinition.getCredentialPublicKey(),
     *                                  null,
     *                                  null);
     *
     * BigInteger proofRequestNonce = BigNumber.random(LARGE_NONCE);
     * Proof proof = proofBuilder.build(proofRequestNonce);
     */
    public Proof build(BigInteger nonce) throws CryptoException {

        List<byte[]> values = new ArrayList<>();
        values.addAll(tau_list);
        values.addAll(c_list);
        values.add(asUnsignedByteArray(nonce));

        // In the anoncreds whitepaper, `challenge` is denoted by `c_h`
        BigInteger challenge = new BigInteger(1, CredentialHelper.hash(values));

        List<SubProof> proofs = new ArrayList<>();

        for(InitProof init_proof : init_proofs) {
            NonRevocProof non_revoc_proof = null;

            if(init_proof.non_revoc_init_proof != null) {
                non_revoc_proof = NonRevocProof.finalize(init_proof.non_revoc_init_proof, challenge);
            }

            PrimaryProof primary_proof = PrimaryProof.finalize(
                    init_proof.primary_init_proof,
                    challenge,
                    init_proof.credential_schema,
                    init_proof.non_credential_schema,
                    init_proof.credential_values,
                    init_proof.sub_proof_request);

            SubProof proof = new SubProof(primary_proof, non_revoc_proof);
            proofs.add(proof);
        }

        AggregatedProof aggregated_proof = new AggregatedProof(challenge, c_list);
        return new Proof(proofs, aggregated_proof);
    }

    private boolean checkAddSubProofRequestParamsConsistency(
            CredentialValues credentialValues,
            SubProofRequest subProofRequest,
            CredentialSchema credentialSchema,
            NonCredentialSchema nonCredentialSchema)
    {
        // Union of two lists
        List<String> schema_attrs = Stream.concat(nonCredentialSchema.attrs.stream(), credentialSchema.attrs.stream())
                .distinct()
                .collect(Collectors.toList());

        List<String> cred_attrs = new ArrayList<>(credentialValues.getValues().keySet());
        Collections.sort(schema_attrs);
        Collections.sort(cred_attrs);

        if(!schema_attrs.equals(cred_attrs)){
            LOG.error("Credential doesn't correspond to credential schema");
            return false;
        }

        if(subProofRequest.revealed_attrs.stream().filter(item -> !cred_attrs.contains(item)).count() != 0){
            LOG.error("Credential doesn't contain requested attribute");
            return false;
        }

        List<String> predicates_attrs = subProofRequest.predicates.stream()
                .map(item -> item.attr_name)
                .collect(Collectors.toList());

        if(predicates_attrs.stream().filter(item -> !cred_attrs.contains(item)).count() != 0){
            LOG.error("Credential doesn't contain attribute requested in predicate");
            return false;
        }

        return true;
    }
}
