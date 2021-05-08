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

public class RevocationRegistryDefinitionValue {

    @JsonProperty("issuanceType")
    public IssuanceType issuance_type;
    @JsonProperty("maxCredNum")
    public int max_cred_num;
    @JsonProperty("publicKeys")
    public RevocationRegistryDefinitionValuePublicKeys public_keys;
    @JsonProperty("tailsHash")
    public String tails_hash;
    @JsonProperty("tailsLocation")
    public String tails_location;

    @JsonCreator
    public RevocationRegistryDefinitionValue(
            @JsonProperty("issuanceType") IssuanceType issuance_type,
            @JsonProperty("maxCredNum") int max_cred_num,
            @JsonProperty("publicKeys") RevocationRegistryDefinitionValuePublicKeys public_keys,
            @JsonProperty("tailsHash") String tails_hash,
            @JsonProperty("tailsLocation") String tails_location)
    {
        this.issuance_type = issuance_type;
        this.max_cred_num = max_cred_num;
        this.public_keys = public_keys;
        this.tails_hash = tails_hash;
        this.tails_location = tails_location;
    }

    public IssuanceType getIssuanceType() {
        return issuance_type;
    }

    public int getMaxCredNum() {
        return max_cred_num;
    }

    public RevocationRegistryDefinitionValuePublicKeys getPublicKeys() {
        return public_keys;
    }

    public String getTailsHash() {
        return tails_hash;
    }

    public String getTailsLocation() {
        return tails_location;
    }
}
