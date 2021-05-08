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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import jssi.credential.credential.AttributeValue;
import jssi.credential.credential.CredentialDefinition;
import jssi.credential.credential.CredentialDefinitionId;
import jssi.credential.proof.*;
import jssi.credential.request.ProofRequestPayload;
import jssi.credential.revocation.RevocationRegistry;
import jssi.credential.revocation.RevocationRegistryDefinition;
import jssi.credential.revocation.RevocationRegistryId;
import jssi.credential.schema.Schema;
import jssi.credential.schema.SchemaId;
import jssi.ursa.credential.query.Query;
import jssi.ursa.credential.query.QueryOp;
import jssi.ursa.credential.CredentialPublicKey;
import jssi.ursa.credential.CredentialSchema;
import jssi.ursa.credential.NonCredentialSchema;
import jssi.ursa.credential.proof.SubProofRequest;
import jssi.ursa.credential.verifier.ProofVerifier;
import jssi.ursa.credential.verifier.Verifier;
import jssi.ursa.pair.CryptoException;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class VerifierService {

    private static final Logger LOG = LoggerFactory.getLogger(VerifierService.class);
    private static final Pattern INTERNAL_TAG_MATCHER = Pattern.compile("^attr::([^:]+)::(value|marker)$");

    public VerifierService(){}

    public boolean verify(
            Proof full_proof,
            ProofRequestPayload proof_req,
            Map<SchemaId, Schema> schemas,
            Map<CredentialDefinitionId, CredentialDefinition> cred_defs,
            Map<RevocationRegistryId, RevocationRegistryDefinition> rev_reg_defs,
            Map<RevocationRegistryId, HashMap<Long, RevocationRegistry>> rev_regs) throws CryptoException {

        Map<String, Identifier> received_revealed_attrs = receivedRevealedAttrs(full_proof);
        Map<String, Identifier> received_unrevealed_attrs = receivedUnrevealedAttrs(full_proof);
        Map<String, Identifier> received_predicates = receivedPredicates(full_proof);
        Set<String> received_self_attested_attrs = receivedSelfAttestedAttrs(full_proof);

        if(!compareAttrFromProofAndRequest(
                proof_req,
                received_revealed_attrs,
                received_unrevealed_attrs,
                received_self_attested_attrs,
                received_predicates)){
            return false;
        }

        if(!verifyRevealedAttributeValues(proof_req, full_proof)){
            return false;
        }

        if(!verifyRequestedRestrictions(
                proof_req,
                full_proof.requested_proof,
                received_revealed_attrs,
                received_unrevealed_attrs,
                received_predicates,
                received_self_attested_attrs)){
            return false;
        }

        if(!compareTimestampsFromProofAndRequest(
                proof_req,
                received_revealed_attrs,
                received_unrevealed_attrs,
                received_self_attested_attrs,
                received_predicates)){
            return false;
        }

        ProofVerifier proof_verifier = Verifier.createProofVerifier();
        NonCredentialSchema non_credential_schema = CredentialHelper.buildNonCredentialSchema();

        for(int sub_proof_index = 0; sub_proof_index < full_proof.identifiers.size(); sub_proof_index++)  {
            Identifier identifier = full_proof.identifiers.get(sub_proof_index);

            Schema schema = schemas.get(identifier.schema_id);
            if(schema == null){
                LOG.error(String.format("Schema not found for id: %s", identifier.schema_id.id));
                return false;
            }

            CredentialDefinition cred_def = cred_defs.get(identifier.cred_def_id);
            if(cred_def == null){
                LOG.error(String.format("CredentialDefinition not found for id: {:?}", identifier.cred_def_id.id));
                return false;
            }

            RevocationRegistry rev_reg = null;
            RevocationRegistryDefinition rev_reg_def = null;

            Long timestamp = identifier.timestamp;
            if(timestamp != null){
                RevocationRegistryId rev_reg_id = identifier.rev_reg_id;
                if(rev_reg_id == null){
                    LOG.error("Revocation Registry Id not found");
                    return false;
                }

                rev_reg_def =  rev_reg_defs.get(rev_reg_id);
                if(rev_reg_def == null){
                    LOG.error(String.format("RevocationRegistryDefinition not found for id: %s", identifier.rev_reg_id.id));
                    return false;
                }

                Map<Long, RevocationRegistry> rev_regs_for_cred = rev_regs.get(rev_reg_id);
                if(rev_regs_for_cred == null){
                    LOG.error(String.format("RevocationRegistry not found for id: %s", rev_reg_id.id));
                    return false;
                }

                rev_reg = rev_regs_for_cred.get(timestamp);
                if(rev_reg == null){
                    LOG.error(String.format("\"RevocationRegistry not found for timestamp: %d", timestamp));
                    return false;
                }
            }

            List<AttributeInfo> attrs_for_credential = getRevealedAttributesForCredential(sub_proof_index, full_proof.requested_proof, proof_req);
            List<PredicateInfo> predicates_for_credential = getPredicatesForCredential(sub_proof_index, full_proof.requested_proof, proof_req);

            CredentialSchema credential_schema = CredentialHelper.buildCredentialSchema(schema.getAttrNames());
            SubProofRequest sub_proof_request = CredentialHelper.buildSubProofRequest(attrs_for_credential, predicates_for_credential);
            CredentialPublicKey credential_pub_key = new CredentialPublicKey(cred_def.value.primary, cred_def.value.revocation);

            proof_verifier.addSubProofRequest(
                    sub_proof_request,
                    credential_schema,
                    non_credential_schema,
                    credential_pub_key,
                    rev_reg_def.value.public_keys.accum_key,
                    rev_reg.value);
        }

        return proof_verifier.verify(full_proof.proof, proof_req.nonce);
    }


    private static Map<String, Identifier> receivedRevealedAttrs(Proof proof)  {

        Map<String, Identifier> map = new HashMap<>();

       for(String referent : proof.requested_proof.revealed_attrs.keySet()){
           RevealedAttributeInfo info = proof.requested_proof.revealed_attrs.get(referent);
           map.put(referent, getProofIdentifier(proof, info.sub_proof_index));
       }

        for(String referent : proof.requested_proof.revealed_attr_groups.keySet()){
            RevealedAttributeGroupInfo info = proof.requested_proof.revealed_attr_groups.get(referent);
            map.put(referent, getProofIdentifier(proof, info.sub_proof_index));
        }

        return map;
    }

    private static Map<String, Identifier> receivedUnrevealedAttrs(Proof proof)  {

        Map<String, Identifier> map = new HashMap<>();

        for(String referent : proof.requested_proof.unrevealed_attrs.keySet()){
            SubProofReferent info = proof.requested_proof.unrevealed_attrs.get(referent);
            map.put(referent, getProofIdentifier(proof, info.sub_proof_index));
        }
        return map;
    }

    private static Map<String, Identifier> receivedPredicates(Proof proof) {

        Map<String, Identifier> map = new HashMap<>();

        for(String referent : proof.requested_proof.predicates.keySet()){
            SubProofReferent info = proof.requested_proof.predicates.get(referent);
            map.put(referent, getProofIdentifier(proof, info.sub_proof_index));
        }
        return map;
    }

    private static Set<String> receivedSelfAttestedAttrs(Proof proof) {
        return proof.requested_proof.self_attested_attrs.keySet();
    }

    private static Identifier getProofIdentifier(Proof proof, int index)  {
        return proof.identifiers.get(index);

    }

    private static boolean verifyRevealedAttributeValues(ProofRequestPayload proof_req, Proof proof){

        for(String attr_referent : proof.requested_proof.revealed_attrs.keySet()){
            RevealedAttributeInfo attr_info = proof.requested_proof.revealed_attrs.get(attr_referent);
            String attr_name = proof_req.requested_attributes.get(attr_referent).name;
            if(!verifyRevealedAttributeValue(attr_name, proof, attr_info)){
                LOG.error(String.format("Attribute with referent \"%s\" not found in ProofRequests", attr_referent));
                return false;
            }
        }

        for(String attr_referent : proof.requested_proof.revealed_attr_groups.keySet()){
            RevealedAttributeGroupInfo attr_infos = proof.requested_proof.revealed_attr_groups.get(attr_referent);
            List<String> attr_names = proof_req.requested_attributes.get(attr_referent).names;
            if(attr_names.size() != attr_infos.values.size()){
                LOG.error(String.format("Proof Revealed Attr Group does not match Proof Request Attribute Group, proof request attrs size: %d, attr_infos size: %s", attr_names.size(), attr_infos.values.size()));
                return false;
            }

            for(String attr_name : attr_names){
                AttributeValue attr_info = attr_infos.values.get(attr_name);
                if(!verifyRevealedAttributeValue(
                        attr_name,
                        proof,
                        new RevealedAttributeInfo(attr_infos.sub_proof_index, attr_info.raw, attr_info.encoded))){
                    LOG.error("Proof Revealed Attr Group does not match Proof Request Attribute Group");
                    return false;
                }
            }
        }
        return true;
    }

    private static List<AttributeInfo> getRevealedAttributesForCredential(
            int sub_proof_index,
            RequestedProof requestedProof,
            ProofRequestPayload proof_req)
    {
        List<AttributeInfo> revealed_attrs_for_credential = new ArrayList<>();

        for(String attrReferent : requestedProof.revealed_attrs.keySet()){
            RevealedAttributeInfo revealed_attr_info = requestedProof.revealed_attrs.get(attrReferent);
            if((sub_proof_index == revealed_attr_info.sub_proof_index) && proof_req.requested_attributes.containsKey(attrReferent)){
                revealed_attrs_for_credential.add(proof_req.requested_attributes.get(attrReferent));
            }
        }

        for(String attrReferent : requestedProof.revealed_attr_groups.keySet()){
            RevealedAttributeInfo revealed_attr_info = requestedProof.revealed_attrs.get(attrReferent);
            if((sub_proof_index == revealed_attr_info.sub_proof_index) && proof_req.requested_attributes.containsKey(attrReferent)){
                revealed_attrs_for_credential.add(proof_req.requested_attributes.get(attrReferent));
            }
        }
        return revealed_attrs_for_credential;
    }

    private static List<PredicateInfo> getPredicatesForCredential(
            int sub_proof_index,
            RequestedProof requestedProof,
            ProofRequestPayload proof_req)
    {
        List<PredicateInfo> predicateInfos = new ArrayList<>();

        for(String predicateReferent : requestedProof.predicates.keySet()){
            SubProofReferent subProofReferent = requestedProof.predicates.get(predicateReferent);
            if((sub_proof_index == subProofReferent.sub_proof_index) && proof_req.requested_predicates.containsKey(predicateReferent)){
                predicateInfos.add(proof_req.requested_predicates.get(predicateReferent));
            }
        }
        return predicateInfos;
    }

    private static boolean isSelfAttested(String referent, AttributeInfo info, Set<String> self_attested_attrs) {

        Query query = info.restrictions;
        if(query.getOp() == QueryOp.And || query.getOp() == QueryOp.Or){
            if(query.getOperators().isEmpty()){
                return self_attested_attrs.contains(referent);
            }
            return false;

        } else {
            return self_attested_attrs.contains(referent);
        }
    }

    private static Filter gatherFilterInfo(String referent, Map<String, Identifier> identifiers) {

        Identifier identifier = identifiers.get(referent);
        if(identifier == null){
            LOG.error(String.format("Identifier not found for referent: %s", referent));
            return null;
        }

        SchemaId.Parts parts = identifier.schema_id.parts();
        if(parts == null){
            LOG.error(String.format("Invalid Schema ID %s: wrong number of parts", identifier.schema_id.id));
            return null;
        }

        String issuer_did = identifier.cred_def_id.getIssuerDid();
        if(issuer_did == null){
            LOG.error(String.format("Invalid Credential Definition ID %s: wrong number of parts", identifier.cred_def_id.id));
            return null;
        }

        return new Filter(
                identifier.schema_id.id,
                parts.did,
                parts.name,
                parts.version,
                issuer_did,
                identifier.cred_def_id.id);
    }

    static boolean processOperator(String attr, Query restrictionOp, Filter filter, String revealed_value)  {
        Map<String, String> map = new HashMap<>();
        map.put(attr, revealed_value);
        return processOperator(map, restrictionOp, filter);
    }

    private static boolean processOperator(Map<String, String> map, Query restrictionOp, Filter filter) {

        switch (restrictionOp.getOp()){
            case Eq: {
                String tag_name = restrictionOp.getKey();
                String tag_value = restrictionOp.getValue();
                if(!processFilter(map, tag_name, tag_value, filter)){
                    LOG.error(String.format("$eq operator validation failed for tag: \"%s\", value: \"%s\"", tag_name, tag_value));
                    return false;
                }
                return true;
            }
            case Neq: {
                String tag_name = restrictionOp.getKey();
                String tag_value = restrictionOp.getValue();
                if(!processFilter(map, tag_name, tag_value, filter)){
                    return true;
                } else {
                    LOG.error(String.format("$neq operator validation failed for tag: \"%s\", value: \"%s\". Condition was passed.", tag_name, tag_value));
                    return false;
                }
            }
            case In:{
                String tag_name = restrictionOp.getKey();
                String tag_values = String.join(",", restrictionOp.getValues());
                boolean result = false;
                for(String tag_value : restrictionOp.getValues()){
                    result |= processFilter(map, tag_name, tag_value, filter);
                }
                if(!result){
                    LOG.error(String.format("$in operator validation failed for tag: \"%s\", value: \"%s\"", tag_name, tag_values));
                    return false;
                }
                return true;
            }
            case And: {
                List<Query> operators = restrictionOp.getOperators();
                for (Query op : operators) {
                    if (!processOperator(map, op, filter)) {
                        LOG.error("$and operator validation failed.");
                        return false;
                    }
                }
                return true;
            }
            case Not:{
                Query op = restrictionOp.getOperators().get(0);
                if(processOperator(map, op, filter)){
                    return false;
                }
                LOG.error("$not operator validation failed. All conditions were passed.");
                return true;
            }
            case Or:{
                List<Query> operators = restrictionOp.getOperators();
                boolean result = false;
                for (Query op : operators) {
                    result |= processOperator(map, op, filter);
                }
                if(!result){
                    LOG.error("$or operator validation failed. All conditions were failed");
                    return false;
                }
                return true;
            }
            default:
                return false;
        }
    }

    private static boolean processFilter(
            Map<String, String> map,
            String tag,
            String tag_value,
            Filter filter)  {

        switch(tag){
            case "schema_id":
                return processField(tag, filter.schema_id, tag_value);
            case "schema_issuer_did":
                return processField(tag, filter.schema_issuer_did, tag_value);
            case "schema_name":
                return processField(tag, filter.schema_name, tag_value);
            case "schema_version":
                return processField(tag, filter.schema_version, tag_value);
            case "cred_def_id":
                return processField(tag, filter.cred_def_id, tag_value);
            case "issuer_did":
                return processField(tag, filter.issuer_did, tag_value);
            default:{
                if(isAttributeInternalTag(tag, map)){
                    return checkInternalTagRevealedValue(tag, tag_value, map);
                }
                if(isAttributeOperator(tag)) {
                    return true;
                }
            }
            LOG.error("Unknown Filter type");
            return false;
        }
    }

    static boolean isAttributeInternalTag(String key, Map<String, String> map) {
        Matcher matcher = INTERNAL_TAG_MATCHER.matcher(key);
        while(matcher.find()) {
            return map.containsKey(matcher.group(1));
        }
        return false;
    }

    static boolean isAttributeOperator(String key) {
        return key.startsWith("attr::") && key.endsWith("::marker");
    }

    private static boolean checkInternalTagRevealedValue(
            String key,
            String tag_value,
            Map<String, String> map) {

        Matcher matcher = INTERNAL_TAG_MATCHER.matcher(key);

        if(!matcher.find()){
            LOG.error("Attribute name became unparseable");
            return false;
        }

        String attr_name = matcher.group(1);
        if(attr_name == null){
            LOG.error("No name has been parsed");
            return false;
        }

        String revealed_value = map.get(attr_name);
        if(revealed_value != null && !revealed_value.equals(tag_value)){
            LOG.error(String.format("\"%s\" values are different: expected: \"%s\", actual: \"%s\"", key, tag_value, revealed_value));
            return false;
        }
        return true;
    }

    private static boolean processField(String filed, String filter_value, String tag_value)  {
        if (filter_value.equals(tag_value)) {
           return true;
        } else {
            LOG.error(String.format("\"%s\" values are different: expected: \"%s\", actual: \"%s\"", filed, tag_value, filter_value));
            return false;
        }
    }


    private static boolean verifyRevealedAttributeValue(String attr_name, Proof proof, RevealedAttributeInfo attr_info) {
        String reveal_attr_encoded = attr_info.encoded;
        int sub_proof_index = attr_info.sub_proof_index;

        Map<String, String> map = proof.proof.proofs.get(sub_proof_index).revealedAttrs();
        String crypto_proof_encoded = null;

        for(String key : map.keySet()){
            if(key.replace(" ", "").equals(attr_name.replace(" ", ""))){
                crypto_proof_encoded = map.get(key);
            }
        }

        if(crypto_proof_encoded == null || crypto_proof_encoded.equals(reveal_attr_encoded)){
            LOG.error(String.format("Attribute with name \"%s\" not found in CryptoProof", attr_name));
            return false;
        }
        return true;
    }

    private static boolean verifyRequestedRestrictions(
            ProofRequestPayload proof_req,
            RequestedProof requested_proof,
            Map<String, Identifier> received_revealed_attrs,
            Map<String, Identifier> received_unrevealed_attrs,
            Map<String, Identifier> received_predicates,
            Set<String> self_attested_attrs)
    {
        Map<String, Identifier> proof_attr_identifiers = new HashMap<>();
        proof_attr_identifiers.putAll(received_revealed_attrs);
        proof_attr_identifiers.putAll(received_unrevealed_attrs);

        Map<String, AttributeInfo> requested_attrs = new HashMap<>();
        for(String referent : proof_req.requested_attributes.keySet()) {
            AttributeInfo info = proof_req.requested_attributes.get(referent);
            if(isSelfAttested(referent, info, self_attested_attrs)){
                requested_attrs.put(referent, info);
            }
        }

        for(String referent : requested_attrs.keySet()) {
            AttributeInfo info = requested_attrs.get(referent);

            Query query = info.restrictions;
            if(query == null){
                return false;
            }

            Filter filter = gatherFilterInfo(referent, proof_attr_identifiers);
            Map<String, String> name_value_map = new HashMap<>();
            if(info.name != null){
                name_value_map.put(info.name, requested_proof.revealed_attrs.get(referent).raw);
            } else if(info.names != null) {
                RevealedAttributeGroupInfo attrs = requested_proof.revealed_attr_groups.get(referent);
                if(attrs == null){
                    LOG.error("Proof does not have referent from proof request");
                    return false;
                }
                for(String name : info.names){
                    String value = attrs.values.get(name).raw;
                    name_value_map.put(name, value);
                }
            } else {
                LOG.error("Proof Request attribute restriction should contain \"name\" or \"names\" param. Current proof request");
            }

            if(!processOperator(name_value_map, query, filter)){
                LOG.error(String.format("Requested restriction validation failed for attributes %s", String.join(",", name_value_map.keySet())));
                return false;
            }
        }

        for(String referent : proof_req.requested_predicates.keySet()){
            PredicateInfo info = proof_req.requested_predicates.get(referent);
            Query query = info.restrictions;
            if(query != null){
                Filter filter = gatherFilterInfo(referent, received_predicates);
                if(!processOperator(info.name, query, filter, null)){
                    LOG.error(String.format("Requested restriction validation failed for \"%s\" predicate", info.name));
                    return false;
                }
            }
        }
        return true;
    }


    private static boolean compareAttrFromProofAndRequest(
            ProofRequestPayload proof_req,
            Map<String, Identifier> received_revealed_attrs,
            Map<String, Identifier> received_unrevealed_attrs,
            Set<String> received_self_attested_attrs,
            Map<String, Identifier> received_predicates){

        Set<String> requested_attrs = proof_req.requested_attributes.keySet();

        // Keys concatenation. This operation effectively
        // modifies this set so that its value is the union of sets
        Set<String> received_attrs = received_revealed_attrs.keySet();
        received_attrs.addAll(received_unrevealed_attrs.keySet());
        received_attrs.addAll(received_self_attested_attrs);


        if (!requested_attrs.equals(received_attrs)) {
            String requested = requested_attrs.stream().map(Object::toString).collect(Collectors.joining(","));
            String received = received_attrs.stream().map(Object::toString).collect(Collectors.joining(","));
            LOG.error(String.format("Requested attributes %s do not correspond to received %s", requested, received));
            return false;
        }

        Set<String> requested_predicates = proof_req.requested_predicates.keySet();
        Set<String> received_predicates_ = received_predicates.keySet();

        if (!requested_predicates.equals(received_predicates_)) {
            String requested = requested_predicates.stream().map(Object::toString).collect(Collectors.joining(","));
            String received = received_predicates_.stream().map(Object::toString).collect(Collectors.joining(","));
            LOG.error(String.format("Requested predicates %s do not correspond to received %s", requested, received));
            return false;
        }

        return true;
    }

    private static boolean compareTimestampsFromProofAndRequest(
            ProofRequestPayload proof_req,
            Map<String, Identifier> received_revealed_attrs,
            Map<String, Identifier> received_unrevealed_attrs,
            Set<String> received_self_attested_attrs,
            Map<String, Identifier> received_predicates) {

        for(String referent : proof_req.requested_attributes.keySet()){
            AttributeInfo info = proof_req.requested_attributes.get(referent);

            if(!validateTimestamp(received_revealed_attrs, referent, proof_req.non_revoked, info.non_revoked) ||
                    !validateTimestamp(received_unrevealed_attrs, referent, proof_req.non_revoked, info.non_revoked) ||
                    !received_self_attested_attrs.contains(referent)){
                return false;
            }
        }

        for(String referent : proof_req.requested_predicates.keySet()){
            PredicateInfo info = proof_req.requested_predicates.get(referent);
            if(!validateTimestamp(received_predicates, referent, proof_req.non_revoked, info.non_revoked)){
                return false;
            }
        }
       return true;
    }

    static boolean validateTimestamp(
            Map<String, Identifier> received,
            String referent,
            NonRevokedInterval globalInterval,
            NonRevokedInterval localInterval)
    {
        if(CredentialHelper.getNonRevocInterval(globalInterval, localInterval) == null) {
            return true;
        }
        if(received.containsKey(referent)){
            return received.get(referent).timestamp != null;
        } else {
            return false;
        }
    }
}
