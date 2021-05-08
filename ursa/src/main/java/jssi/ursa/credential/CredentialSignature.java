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

package jssi.ursa.credential;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

public class CredentialSignature {

    public PrimaryCredentialSignature p_credential;
    public NonRevocationCredentialSignature r_credential; /* will be used to proof is credential revoked preparation */

    @JsonCreator
    public CredentialSignature(
            @JsonProperty("p_credential") PrimaryCredentialSignature p_credential,
            @JsonProperty("r_credential") NonRevocationCredentialSignature r_credential)
    {
        this.p_credential = p_credential;
        this.r_credential = r_credential;
    }

    @JsonIgnore
    public int getIndex(){
        return  r_credential.index;
    }
}
