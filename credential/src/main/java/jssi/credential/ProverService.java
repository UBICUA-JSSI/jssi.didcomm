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

import jssi.credential.credential.CredentialDefinition;
import jssi.ursa.credential.CredentialValues;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import jssi.credential.credential.*;
import jssi.credential.offer.CredentialOffer;
import jssi.credential.proof.*;
import jssi.credential.request.*;
import jssi.credential.revocation.RevocationRegistryDefinition;
import jssi.credential.revocation.RevocationRegistryId;
import jssi.credential.revocation.RevocationState;
import jssi.credential.schema.Schema;
import jssi.credential.schema.SchemaId;
import jssi.ursa.credential.query.Query;
import jssi.ursa.credential.query.QueryOp;
import jssi.ursa.credential.*;
import jssi.ursa.credential.proof.ProofBuilder;
import jssi.ursa.credential.proof.SubProofRequest;
import jssi.ursa.credential.prover.Prover;
import jssi.ursa.pair.CryptoException;

import java.util.*;
import java.util.stream.Collectors;

public class ProverService {

    private static final Logger LOG = LoggerFactory.getLogger(ProverService.class);
    public static final String ATTRIBUTE_EXISTENCE_MARKER = "1";

    public ProverService(){}

    public BlindedCredentials createCredentialRequest(
            CredentialDefinition credentialDefinition,
            MasterSecret masterSecret,
            CredentialOffer credentialOffer)
    {
        CredentialPublicKey credentialPublicKey = new CredentialPublicKey(
                credentialDefinition.value.primary,
                credentialDefinition.value.revocation);

        CredentialValues.CredentialValuesBuilder builder = CredentialValues.builder();
        builder.addHidden("master_secret", masterSecret.getValue().ms);
        CredentialValues credentialValues = builder.build();

        return Prover.blindCredentialSecrets(
                credentialPublicKey,
                credentialOffer.key_correctness_proof,
                credentialValues,
                credentialOffer.nonce);

    }

    public boolean processCredential(
            Credential credential,
            CredentialRequestMetadata credentialRequestMetadata,
            MasterSecret masterSecret,
            CredentialDefinition credentialDefinition,
            RevocationRegistryDefinition revocationRegistryDefinition) throws CryptoException {

        CredentialPublicKey credentialPublicKey = new CredentialPublicKey(
                credentialDefinition.value.primary,
                credentialDefinition.value.revocation);

        CredentialValues credentialValues = CredentialHelper.buildCredentialValues(credential.values, masterSecret);

        return Prover.processCredentialSignature(
                credential.signature,
                credentialValues,
                credential.signatureCorrectnessProof,
                credentialRequestMetadata.master_secret_blinding_data,
                credentialPublicKey,
                credentialRequestMetadata.nonce,
                revocationRegistryDefinition.value.public_keys.accum_key,
                credential.revocationRegistry,
                credential.witness);
    }

    public Proof createProof(
            Map<String, Credential> credentials,
            ProofRequest proofRequest,
            RequestedCredentials requestedCredentials,
            jssi.credential.MasterSecret masterSecret,
            Map<SchemaId, Schema> schemas,
            Map<CredentialDefinitionId, CredentialDefinition> credentialDefinitions,
            Map<RevocationRegistryId, Map<Long, RevocationState>> revocationStates) throws CryptoException
    {
        ProofRequestPayload proofRequestPayload = proofRequest.getValue();
        ProofBuilder builder = new ProofBuilder();
        builder.addCommonAttr("master_secret");

        RequestedProof requestedProof = new RequestedProof();
        requestedProof.self_attested_attrs = requestedCredentials.self_attested_attributes;

        Map<ProvingCredentialKey, PreparedCredentialsValues> credentials_for_proving = prepareCredentialsForProving(
                requestedCredentials,
                proofRequestPayload);

        int sub_proof_index = 0;
        NonCredentialSchema nonCredentialSchema = CredentialHelper.buildNonCredentialSchema();

        List<Identifier> identifiers = new ArrayList<>(credentials_for_proving.size());

        for(ProvingCredentialKey key : credentials_for_proving.keySet()){
            List<RequestedAttributeInfo> requestedAttributes =  credentials_for_proving.get(key).requestedAttributeInfo;
            List<RequestedPredicateInfo> requestedPredicates =  credentials_for_proving.get(key).requestedPredicateInfo;

            Credential credential = credentials.get(key.cred_id);
            if(credential == null){
                LOG.error(String.format("Credential not found by id: %s", key.cred_id));
                return null;
            }

            Schema schema = schemas.get(credential.schemaId);
            if(schema == null){
                LOG.error(String.format("Schema not found by id: %s", credential.schemaId.id));
                return null;
            }

            CredentialDefinition credentialDefinition = credentialDefinitions.get(credential.credentialDefinitionId);
            if(credentialDefinition == null){
                LOG.error(String.format("CredentialDefinition not found by id: %s", credential.credentialDefinitionId.id));
                return null;
            }

            RevocationState revocationState = null;
            if(key.timestamp != null){
                RevocationRegistryId revocationRegistryId = credential.revocationRegistryId;
                if(revocationRegistryId == null){
                    LOG.error("Revocation Registry Id not found");
                    return null;
                }
                Map<Long, RevocationState> revocationTimestampsStates = revocationStates.get(revocationRegistryId);
                if(revocationTimestampsStates == null){
                    LOG.error(String.format("RevocationState not found by id: %s", revocationRegistryId.id));
                    return null;
                }
                revocationState = revocationTimestampsStates.get(key.timestamp);
            }

            CredentialPublicKey credentialPublicKey = new CredentialPublicKey(
                    credentialDefinition.value.primary,
                    credentialDefinition.value.revocation);

            CredentialSchema credentialSchema = CredentialHelper.buildCredentialSchema(schema.getAttrNames());
            CredentialValues credentialValues = CredentialHelper.buildCredentialValues(credential.values, masterSecret);
            SubProofRequest subProofRequest = buildSubProofRequest(requestedAttributes, requestedPredicates);

            builder.addSubProofRequest(
                    subProofRequest,
                    credentialSchema,
                    nonCredentialSchema,
                    credential.signature,
                    credentialValues,
                    credentialPublicKey,
                    revocationState.rev_reg,
                    revocationState.witness);

            Identifier identifier = new Identifier(
                    credential.schemaId,
                    credential.credentialDefinitionId,
                    credential.revocationRegistryId,
                    key.timestamp);

            identifiers.add(identifier);
            updateRequestedProof(
                    requestedAttributes,
                    requestedPredicates,
                    proofRequestPayload,
                    credential,
                    sub_proof_index,
                    requestedProof);

            sub_proof_index += 1;
        }

        jssi.ursa.credential.proof.Proof proof = builder.build(proofRequestPayload.nonce);
        return new Proof(proof, requestedProof, identifiers);
    }

    private void updateRequestedProof(
            List<RequestedAttributeInfo> RequestedAttributes,
            List<RequestedPredicateInfo> requestedPredicates,
            ProofRequestPayload proofRequestPayload,
            Credential credential,
            int sub_proof_index,
            RequestedProof requestedProof) {

        for(RequestedAttributeInfo requestedAttributeInfo : RequestedAttributes) {
            if (requestedAttributeInfo.revealed) {
                AttributeInfo attributeInfo = proofRequestPayload.requested_attributes.get(requestedAttributeInfo.attr_referent);

                if(attributeInfo.name != null) {
                    AttributeValue attributeValue = getCredentialValuesForAttribute(credential.values, attributeInfo.name);
                    if(attributeValue == null){
                        LOG.error(String.format("Credential value not found for attribute %s", attributeInfo.name));
                        return;
                    }

                    requestedProof.revealed_attrs.put(requestedAttributeInfo.attr_referent, new RevealedAttributeInfo(
                            sub_proof_index,
                            attributeValue.raw,
                            attributeValue.encoded));

                } else if(attributeInfo.names != null) {
                    Map<String, AttributeValue> attributeValues = new HashMap<>();
                    for(String name : attributeInfo.names) {
                        AttributeValue attributeValue = getCredentialValuesForAttribute(credential.values, name);
                        if(attributeValue == null){
                            LOG.error(String.format("Credential value not found for attribute %s", name));
                            return;
                        }
                        attributeValues.put(name, new AttributeValue(attributeValue.raw, attributeValue.encoded));
                    }

                    requestedProof.revealed_attr_groups.put(requestedAttributeInfo.attr_referent, new RevealedAttributeGroupInfo(
                            sub_proof_index,
                            attributeValues));
                }
            } else {
                requestedProof.unrevealed_attrs.put(requestedAttributeInfo.attr_referent, new SubProofReferent(sub_proof_index));
            }
        }

        for(RequestedPredicateInfo requestedPredicateInfo : requestedPredicates) {
            requestedProof.predicates.put(requestedPredicateInfo.predicate_referent, new SubProofReferent(sub_proof_index));
        }
    }

    public AttributeValue getCredentialValuesForAttribute(
           Map<String, AttributeValue> credentialAttributes,
            String attribute)
    {
        for(String key : credentialAttributes.keySet()){
            if(CredentialHelper.replace(key).equals(CredentialHelper.replace(attribute))){
                return credentialAttributes.get(key);
            }
        }
        return null;
    }

    public Map<String, String> buildCredentialTags(
            Credential credential,
            CredentialAttrTagPolicy credentialAttrTagPolicy)
    {

        Map<String, String> credentialTags = new HashMap<>();

        SchemaId.Parts parts = credential.schemaId.parts();
        if(parts == null){
            LOG.error(String.format("Invalid Schema ID %s: wrong number of parts", credential.schemaId.id));
            return null;
        }

        String issuerDid = credential.credentialDefinitionId.getIssuerDid();
        if(issuerDid == null){
            LOG.error(String.format("Invalid Credential Definition ID %s: wrong number of parts", credential.credentialDefinitionId.id));
            return null;
        }

        credentialTags.put("schema_id", credential.schemaId.id);
        credentialTags.put("schema_issuer_did", parts.did);
        credentialTags.put("schema_name", parts.name);
        credentialTags.put("schema_version", parts.version);
        credentialTags.put("issuer_did", issuerDid);
        credentialTags.put("cred_def_id", credential.credentialDefinitionId.id);
        credentialTags.put("rev_reg_id", credential.revocationRegistryId == null ? null :  credential.revocationRegistryId.id);

//        if credential.cred_def_id.is_fully_qualified() {
//            res.insert(Credential::add_extra_tag_suffix("schema_id"), credential.schema_id.to_unqualified().0);
//            res.insert(Credential::add_extra_tag_suffix("schema_issuer_did"), schema_issuer_did.to_unqualified().0);
//            res.insert(Credential::add_extra_tag_suffix("issuer_did"), issuer_did.to_unqualified().0);
//            res.insert(Credential::add_extra_tag_suffix("cred_def_id"), credential.cred_def_id.to_unqualified().0);
//            res.insert(Credential::add_extra_tag_suffix("rev_reg_id"), credential.rev_reg_id.as_ref().map(|rev_reg_id| rev_reg_id.to_unqualified().0.clone()).unwrap_or_else(|| "None".to_string()));
//        }

        for(String attribute : credential.values.keySet()){
            AttributeValue value = credential.values.get(attribute);
            if(credentialAttrTagPolicy == null ||credentialAttrTagPolicy.isTaggable(attribute)) {
                credentialTags.put(String.format("attr::%s::marker", CredentialHelper.replace(attribute)), ATTRIBUTE_EXISTENCE_MARKER);
                credentialTags.put(String.format("attr::%s::value", CredentialHelper.replace(attribute)), value.raw);
            }
        }
       return credentialTags;
    }

    public boolean attributeSatisfyPredicate(PredicateInfo predicate, String attribute_value) throws NumberFormatException{

        switch (predicate.p_type) {
            case GE: {
                int value = Integer.parseInt(attribute_value);
                return value >= predicate.p_value;
            }
            case GT: {
                int value = Integer.parseInt(attribute_value);
                return value > predicate.p_value;
            }
            case LE: {
                int value = Integer.parseInt(attribute_value);
                return value <= predicate.p_value;
            }
            case LT: {
                int value = Integer.parseInt(attribute_value);
                return value < predicate.p_value;
            }
            default:
                return false;
        }
    }

    static Map<ProvingCredentialKey, PreparedCredentialsValues> prepareCredentialsForProving(
            RequestedCredentials requestedCredentials,
            ProofRequestPayload proofRequestPayload)
    {

        Map<ProvingCredentialKey, PreparedCredentialsValues> result = new HashMap<>();

        for(String attribute : requestedCredentials.requested_attributes.keySet()){
            RequestedAttribute requestedAttribute = requestedCredentials.requested_attributes.get(attribute);
            AttributeInfo attributeInfo = proofRequestPayload.requested_attributes.get(attribute);
            if(attributeInfo == null){
                LOG.error(String.format("AttributeInfo not found in ProofRequest for referent %s", attribute));
                return null;
            }

            RequestedAttributeInfo requestedAttributeInfo = new RequestedAttributeInfo(
                    attribute,
                    attributeInfo,
                    requestedAttribute.revealed);

            ProvingCredentialKey provingCredentialKey = new ProvingCredentialKey(requestedAttribute.cred_id, requestedAttribute.timestamp);
            if(result.containsKey(provingCredentialKey)){
                PreparedCredentialsValues preparedCredentialsValues = result.get(provingCredentialKey);
                preparedCredentialsValues.requestedAttributeInfo.add(requestedAttributeInfo);
            } else {
                PreparedCredentialsValues preparedCredentialsValues = new PreparedCredentialsValues();
                preparedCredentialsValues.requestedAttributeInfo.add(requestedAttributeInfo);
                result.put(provingCredentialKey, preparedCredentialsValues);
            }
        }

        for(String predicate : requestedCredentials.requested_predicates.keySet()){
            ProvingCredentialKey provingCredentialKey = requestedCredentials.requested_predicates.get(predicate);
            PredicateInfo predicateInfo = proofRequestPayload.requested_predicates.get(predicate);
            if(predicateInfo == null){
                LOG.error(String.format("PredicateInfo not found in ProofRequest for referent %s", predicate));
                return null;
            }

            RequestedPredicateInfo requestedPredicateInfo = new RequestedPredicateInfo(
                    predicate,
                    predicateInfo);

            if(result.containsKey(provingCredentialKey)){
                PreparedCredentialsValues preparedCredentialsValues = result.get(provingCredentialKey);
                preparedCredentialsValues.requestedPredicateInfo.add(requestedPredicateInfo);
            } else {
                PreparedCredentialsValues preparedCredentialsValues = new PreparedCredentialsValues();
                preparedCredentialsValues.requestedPredicateInfo.add(requestedPredicateInfo);
                result.put(provingCredentialKey, preparedCredentialsValues);
            }
        }
        return result;
    }

    private static SubProofRequest buildSubProofRequest(
            List<RequestedAttributeInfo> requestedAttributes,
            List<RequestedPredicateInfo> requestedPredicates)
    {

        SubProofRequest.SubProofRequestBuilder builder = SubProofRequest.builder();

        for(RequestedAttributeInfo attr : requestedAttributes) {
            if (attr.revealed) {
                if(attr.attr_info.name != null) {
                    builder.addRevealedAttr(CredentialHelper.replace(attr.attr_info.name));
                } else if(attr.attr_info.names != null) {
                    for(String name : attr.attr_info.names) {
                        builder.addRevealedAttr(CredentialHelper.replace(name));
                    }
                }
            }
        }

        for(RequestedPredicateInfo predicate : requestedPredicates) {
            String p_type = predicate.predicate_info.p_type.name();
            builder.addPredicate(
                    CredentialHelper.replace(predicate.predicate_info.name),
                    p_type,
                    predicate.predicate_info.p_value);
        }
       return builder.build();
    }

    Query doubleRestrictions(Query operator) {
        switch (operator.getOp()){
            case Eq:{
                if(Arrays.asList(Credential.QUALIFIABLE_TAGS).contains(operator.getKey())){
                    List<Query> operators = new ArrayList<>();
                    operators.add(new Query(QueryOp.Eq, operator.getKey(), operator.getValue()));
                    operators.add(new Query(QueryOp.Eq, Credential.addExtraTagSuffix(operator.getKey()), operator.getValue()));
                    return new Query(QueryOp.Or, operators);
                } else {
                    return new Query(QueryOp.Eq, operator.getKey(), operator.getValue());
                }
            }
            case Neq:{
                if(Arrays.asList(Credential.QUALIFIABLE_TAGS).contains(operator.getKey())){
                    List<Query> operators = new ArrayList<>();
                    operators.add(new Query(QueryOp.Neq, operator.getKey(), operator.getValue()));
                    operators.add(new Query(QueryOp.Neq, Credential.addExtraTagSuffix(operator.getKey()), operator.getValue()));
                    return new Query(QueryOp.And, operators);
                } else {
                    return new Query(QueryOp.Neq, operator.getKey(), operator.getValue());
                }
            }
            case In:{
                if(Arrays.asList(Credential.QUALIFIABLE_TAGS).contains(operator.getKey())){
                    List<Query> operators = new ArrayList<>();
                    operators.add(new Query(QueryOp.In, operator.getKey(), operator.getValues()));
                    operators.add(new Query(QueryOp.In, Credential.addExtraTagSuffix(operator.getKey()), operator.getValues()));
                    return new Query(QueryOp.Or, operators);
                } else {
                    return new Query(QueryOp.In, operator.getKey(), operator.getValues());
                }
            }
            case And:{
                List<Query> operators = operator.getOperators();
                List<Query> result = operators.stream().map(this::doubleRestrictions).collect(Collectors.toList());
                return new Query(QueryOp.And, result);
            }
            case Or:{
                List<Query> operators = operator.getOperators();
                List<Query> result = operators.stream().map(this::doubleRestrictions).collect(Collectors.toList());
                return new Query(QueryOp.Or, result);
            }
            case Not:{
                List<Query> operators = operator.getOperators();
                List<Query> result = operators.stream().map(this::doubleRestrictions).collect(Collectors.toList());
                return new Query(QueryOp.Not, result);
            }
            default:
                LOG.error("Unsupported operator");
                return null;
        }
    }

    public Query extendProofRequestRestrictions(
            ProofRequestsVersion version,
            String name,
            List<String> names,
            String referent,
            Query restrictions,
            Map<String, Query> extraQuery)
    {
        List<Query> queries = new ArrayList<>();

        if(names == null && name == null){
            LOG.error("Proof Request attribute restriction should contain \"name\" or \"names\" param");
            return null;
        } else if(names == null){
            names = new ArrayList<>();
            names.add(name);
        }

        for(String item : names){
            queries.add(new Query(QueryOp.Eq, String.format("attr::%s::marker", CredentialHelper.replace(item)), ATTRIBUTE_EXISTENCE_MARKER));
        }

        if(restrictions != null){
            queries.add(restrictions);
        }

        if(extraQuery != null){
            queries.add(extraQuery.get(referent));
        }

        return new Query(QueryOp.And, queries);
    }

}
