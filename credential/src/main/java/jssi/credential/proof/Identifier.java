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

package jssi.credential.proof;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import jssi.credential.credential.CredentialDefinitionId;
import jssi.credential.revocation.RevocationRegistryId;
import jssi.credential.schema.SchemaId;

public class Identifier {

    public SchemaId schema_id;
    public CredentialDefinitionId cred_def_id;
    public RevocationRegistryId rev_reg_id;
    public Long timestamp;

    @JsonCreator
    public Identifier(
            @JsonProperty("schema_id") SchemaId schema_id,
            @JsonProperty("cred_def_id") CredentialDefinitionId cred_def_id,
            @JsonProperty("rev_reg_id") RevocationRegistryId rev_reg_id,
            @JsonProperty("timestamp") Long timestamp)
    {
        this.schema_id = schema_id;
        this.cred_def_id = cred_def_id;
        this.rev_reg_id = rev_reg_id;
        this.timestamp = timestamp;
    }

    public String getSchema_id() {
        return schema_id.id;
    }

    public String getCred_def_id() {
        return cred_def_id.id;
    }

    public String getRev_reg_id() {
        return rev_reg_id == null ? null : rev_reg_id.id;
    }
}
