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
import jssi.credential.proof.AttributeInfo;
import jssi.credential.proof.NonRevokedInterval;
import jssi.credential.proof.PredicateInfo;
import jssi.ursa.credential.CredentialSchema;
import jssi.ursa.credential.CredentialValues;
import jssi.ursa.credential.NonCredentialSchema;
import jssi.ursa.credential.proof.SubProofRequest;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class CredentialHelper {

    private static final Logger LOG = LoggerFactory.getLogger(CredentialHelper.class);

    public static CredentialSchema buildCredentialSchema(Set<String> attrs) {

        CredentialSchema.CredentialSchemaBuilder builder = CredentialSchema.builder();

        for (String attr : attrs) {
            builder.addAttr(attr.replace(" ", ""));
        }

        return builder.build();
    }

    public static NonCredentialSchema buildNonCredentialSchema() {

        NonCredentialSchema.NonCredentialSchemaBuilder builder = NonCredentialSchema.builder();
        builder.addAttr("master_secret");
        return builder.build();
    }

    public static CredentialValues buildCredentialValues(
            jssi.credential.credential.CredentialValues credential_values,
            MasterSecret master_secret)  {

        CredentialValues.CredentialValuesBuilder builder = CredentialValues.builder();

        for (String attr : credential_values.keySet()) {
            AttributeValue value = credential_values.get(attr);
            builder.addKnown(attr.replace(" ", ""), value.encoded);
        }

        if(master_secret != null) {
            builder.addHidden("master_secret", master_secret.getValue().ms);
        }

        return builder.build();
    }

    public static NonRevokedInterval getNonRevocInterval(NonRevokedInterval global_interval, NonRevokedInterval local_interval) {
        return local_interval != null ? local_interval : global_interval;
    }

    public static SubProofRequest buildSubProofRequest(
            List<AttributeInfo> attrs_for_credential,
            List<PredicateInfo> predicates_for_credential)
    {

        SubProofRequest.SubProofRequestBuilder builder = SubProofRequest.builder();

        List<String> names = new ArrayList<>();
        for(AttributeInfo attr : attrs_for_credential) {
            if(attr.name != null){
                names.add(attr.name);
            } else if(attr.names != null){
                names = attr.names;
            } else {
                LOG.error("Attr for credential restriction should contain \"name\" or \"names\" param");
                return null;
            }

            for(String name : names) {
                builder.addRevealedAttr(name.replace(" ", ""));
            }
        }

        for(PredicateInfo predicate : predicates_for_credential){
            String p_type = predicate.p_type.name();
            builder.addPredicate(predicate.name.replace(" ", ""), p_type, predicate.p_value);
        }

        return builder.build();
    }

    public static String replace(String attribute){
        return attribute.replace(" ", "").toLowerCase();
    }
}
