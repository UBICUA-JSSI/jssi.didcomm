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

package jssi.ursa.credential.proof;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.HashMap;
import java.util.Map;

public class SubProof {

    public PrimaryProof primary_proof;
    public NonRevocProof non_revoc_proof;

    @JsonCreator
    public SubProof(
            @JsonProperty("primary_proof") PrimaryProof primary_proof,
            @JsonProperty("non_revoc_proof") NonRevocProof non_revoc_proof)
    {
        this.primary_proof = primary_proof;
        this.non_revoc_proof = non_revoc_proof;
    }

    public Map<String, String> revealedAttrs()  {
        Map<String, String> result = new HashMap<>();
        for(String key : primary_proof.eq_proof.revealed_attrs.keySet()){
            result.put(key, primary_proof.eq_proof.revealed_attrs.get(key).toString());
        }
        return result;
    }
}
