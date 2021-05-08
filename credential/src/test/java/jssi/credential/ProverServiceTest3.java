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

import org.junit.jupiter.api.Test;
import jssi.credential.proof.AttributeInfo;
import jssi.credential.proof.PredicateInfo;
import jssi.credential.proof.PredicateTypes;
import jssi.credential.request.ProofRequestPayload;
import jssi.credential.request.ProvingCredentialKey;
import jssi.credential.request.RequestedAttribute;
import jssi.credential.request.RequestedCredentials;
import jssi.ursa.credential.util.BigNumber;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static jssi.ursa.credential.util.BigNumber.LARGE_NONCE;

class ProverServiceTest3 {

    private static String CRED_ID = "8591bcac-ee7d-4bef-ba7e-984696440b30";
    private static String ATTRIBUTE_REFERENT = "attribute_referent";
    private static String PREDICATE_REFERENT = "predicate_referent";

    private AttributeInfo attr_info() {
        return new AttributeInfo(
                "name",
                null,
                null,
                null);
    }

    private PredicateInfo predicate_info() {
        return new PredicateInfo(
                "age",
                PredicateTypes.GE,
                8,
                null,
                null);
    }

    private ProofRequestPayload proof_req() {

        BigInteger nonce =  BigNumber.random(LARGE_NONCE);
        Map<String, AttributeInfo> requested_attributes = new HashMap<>();
        requested_attributes.put(ATTRIBUTE_REFERENT, attr_info());
        Map<String, PredicateInfo> requested_predicates = new HashMap<>();
        requested_predicates.put(PREDICATE_REFERENT, predicate_info());

        return new ProofRequestPayload(
                nonce,
                "Job-Application",
                "0.1",
                requested_attributes,
                requested_predicates,
                null);
    }

    private RequestedCredentials req_cred() {

        Map<String, String> self_attested_attributes = new HashMap<>();
        Map<String, RequestedAttribute> requested_attributes = new HashMap<>();
        requested_attributes.put(ATTRIBUTE_REFERENT, new RequestedAttribute(CRED_ID, null, false));
        Map<String, ProvingCredentialKey> requested_predicates = new HashMap<>();
        requested_predicates.put(PREDICATE_REFERENT, new ProvingCredentialKey(CRED_ID, null));

        return new RequestedCredentials(
                self_attested_attributes,
                requested_attributes,
                requested_predicates);
    }

    @Test
    void prepareCredentialsForProving() {
        ProverService ps = new ProverService();
        RequestedCredentials req_cred = req_cred();
        ProofRequestPayload proof_req = proof_req();

        Map<ProvingCredentialKey, PreparedCredentialsValues> result = ProverService.prepareCredentialsForProving(req_cred, proof_req);


        assertEquals(1, result.size());
        assertTrue(result.containsKey( new ProvingCredentialKey(CRED_ID, null)));

        PreparedCredentialsValues values = result.get(new ProvingCredentialKey(CRED_ID, null));
        assertEquals(1, values.requestedAttributeInfo.size());
        assertEquals(1, values.requestedPredicateInfo.size());

        req_cred.requested_attributes.put("attribute_referent_2", new RequestedAttribute(
                CRED_ID,
                null,
                false));

        proof_req.requested_attributes.put("attribute_referent_2", new AttributeInfo(
                "last_name",
                    null,
                    null,
                    null));

        result = ProverService.prepareCredentialsForProving(req_cred, proof_req);

        assertEquals(1, result.size());
        assertTrue(result.containsKey( new ProvingCredentialKey(CRED_ID, null)));

        values = result.get(new ProvingCredentialKey(CRED_ID, null));
        assertEquals(2, values.requestedAttributeInfo.size());
        assertEquals(1, values.requestedPredicateInfo.size());
     }
}