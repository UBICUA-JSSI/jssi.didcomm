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
import jssi.credential.schema.SchemaId;

public class CredentialDefinition {

    public CredentialDefinitionId id;
    @JsonProperty("schemaId")
    public SchemaId schema_id;
    @JsonProperty("type")
    public SignatureType signature_type;
    public String tag;
    public CredentialDefinitionData value;

    @JsonCreator
    public CredentialDefinition(
            @JsonProperty("id") CredentialDefinitionId id,
            @JsonProperty("schemaId") SchemaId schema_id,
            @JsonProperty("type") SignatureType signature_type,
            @JsonProperty("tag") String tag,
            @JsonProperty("value") CredentialDefinitionData value)
    {
        this.id = id;
        this.schema_id = schema_id;
        this.signature_type = signature_type;
        this.tag = tag;
        this.value = value;
    }

    public SignatureType getType() {
        return signature_type;
    }

    public String getId() {
        return id.id;
    }

    public String getSchemaId() {
        return schema_id.id;
    }
}
