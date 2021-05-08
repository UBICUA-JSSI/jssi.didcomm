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
import jssi.ursa.registry.RevocationPublicKey;

public class RevocationRegistryDefinitionValuePublicKeys {
    @JsonProperty("accumKey")
    public RevocationPublicKey accum_key;

    @JsonCreator
    public RevocationRegistryDefinitionValuePublicKeys(
            @JsonProperty("accumKey") RevocationPublicKey accum_key)
    {
        this.accum_key = accum_key;
    }

    public RevocationPublicKey getAccumKey() {
        return accum_key;
    }
}
