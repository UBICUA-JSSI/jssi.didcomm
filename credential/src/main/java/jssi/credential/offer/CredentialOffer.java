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

package jssi.credential.offer;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import jssi.credential.credential.CredentialDefinitionId;
import jssi.credential.schema.SchemaId;
import jssi.ursa.credential.CredentialKeyCorrectnessProof;
import jssi.ursa.credential.util.BigIntegerSerializer;

import java.math.BigInteger;

public class CredentialOffer {
    public @JsonProperty("schema_id")
    SchemaId schemaId;
    public @JsonProperty("cred_def_id")
    CredentialDefinitionId credentialDefinitionId;
    public @JsonProperty("key_correctness_proof")
    CredentialKeyCorrectnessProof key_correctness_proof;
    @JsonSerialize(using = BigIntegerSerializer.class)
    public @JsonProperty("nonce") BigInteger nonce;
    public String method_name;


    @JsonCreator
    public CredentialOffer(
            @JsonProperty("schema_id") SchemaId schemaId,
            @JsonProperty("cred_def_id") CredentialDefinitionId credentialDefinitionId,
            @JsonProperty("key_correctness_proof") CredentialKeyCorrectnessProof key_correctness_proof,
            @JsonProperty("nonce") BigInteger nonce)
    {
        this(schemaId, credentialDefinitionId, key_correctness_proof, nonce, null);
    }

    public CredentialOffer(
            SchemaId schemaId,
            CredentialDefinitionId credentialDefinitionId,
            CredentialKeyCorrectnessProof key_correctness_proof,
            BigInteger nonce,
            String method_name)
    {
        this.schemaId = schemaId;
        this.credentialDefinitionId = credentialDefinitionId;
        this.key_correctness_proof = key_correctness_proof;
        this.nonce = nonce;
        this.method_name = method_name;
    }

    public String getSchemaId() {
        return schemaId.id;
    }

    public String getCredentialDefinitionId() {
        return credentialDefinitionId.id;
    }


}
