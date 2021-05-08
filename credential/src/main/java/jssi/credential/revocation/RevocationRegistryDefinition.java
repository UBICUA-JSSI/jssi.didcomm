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

package jssi.credential.revocation;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import jssi.credential.credential.CredentialDefinitionId;

public class RevocationRegistryDefinition {

    public RevocationRegistryId id;
    @JsonProperty("revocDefType")
    public RegistryType revoc_def_type;
    public String tag;
    @JsonProperty("credDefId")
    public CredentialDefinitionId cred_def_id;
    public RevocationRegistryDefinitionValue value;

    @JsonCreator
    public RevocationRegistryDefinition(
            @JsonProperty("id") RevocationRegistryId id,
            @JsonProperty("revocDefType") RegistryType revoc_def_type,
            @JsonProperty("tag") String tag,
            @JsonProperty("credDefId") CredentialDefinitionId cred_def_id,
            @JsonProperty("value") RevocationRegistryDefinitionValue value)
    {
        this.id = id;
        this.revoc_def_type = revoc_def_type;
        this.tag = tag;
        this.cred_def_id = cred_def_id;
        this.value = value;
    }

    public String getId() {
        return id.id;
    }

    public RegistryType getRevocDefType() {
        return revoc_def_type;
    }

    public String getCredDefId() {
        return cred_def_id.id;
    }
}
