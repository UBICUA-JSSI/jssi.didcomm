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

package jssi.credential.credential;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import jssi.credential.revocation.RevocationRegistryId;
import jssi.credential.schema.SchemaId;
import jssi.ursa.credential.CredentialSignature;
import jssi.ursa.credential.SignatureCorrectnessProof;
import jssi.ursa.registry.RevocationRegistry;
import jssi.ursa.registry.Witness;

public class Credential {

    public static final String TYPE = "Indy::Credential";
    public static final String[] QUALIFIABLE_TAGS = new String[]{"issuer_did", "cred_def_id", "schema_id", "schema_issuer_did", "rev_reg_id"};
    public static final String EXTRA_TAG_SUFFIX = "_short";

    public @JsonProperty("schema_id") SchemaId schemaId;
    public @JsonProperty("cred_def_id") CredentialDefinitionId credentialDefinitionId;
    public @JsonProperty("rev_reg_id")
    RevocationRegistryId revocationRegistryId;
    public @JsonProperty("values") CredentialValues values;
    public @JsonProperty("signature")
    CredentialSignature signature;
    public @JsonProperty("signature_correctness_proof")
    SignatureCorrectnessProof signatureCorrectnessProof;
    public @JsonProperty("rev_reg") RevocationRegistry revocationRegistry;
    public @JsonProperty("witness") Witness witness;

    @JsonCreator
    public Credential(
            @JsonProperty("schema_id") SchemaId schemaId,
            @JsonProperty("cred_def_id") CredentialDefinitionId credentialDefinitionId,
            @JsonProperty("rev_reg_id") RevocationRegistryId revocationRegistryId,
            @JsonProperty("values") CredentialValues values,
            @JsonProperty("signature") CredentialSignature signature,
            @JsonProperty("signature_correctness_proof") SignatureCorrectnessProof signatureCorrectnessProof,
            @JsonProperty("rev_reg") RevocationRegistry revocationRegistry,
            @JsonProperty("witness") Witness witness)
    {
        this.schemaId = schemaId;
        this.credentialDefinitionId = credentialDefinitionId;
        this.revocationRegistryId = revocationRegistryId;
        this.values = values;
        this.signature = signature;
        this.signatureCorrectnessProof = signatureCorrectnessProof;
        this.revocationRegistry = revocationRegistry;
        this.witness = witness;
    }

    public String getSchemaId() {
        return schemaId.id;
    }

    public String getCredentialDefinitionId() {
        return credentialDefinitionId.id;
    }

    public String getRevocationRegistryId() {
        return revocationRegistryId == null ? null : revocationRegistryId.id;
    }

    public static String addExtraTagSuffix(String tag){
        return String.format("%s%s", tag, EXTRA_TAG_SUFFIX);
    }
}
