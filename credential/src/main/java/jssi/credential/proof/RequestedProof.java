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

import java.util.HashMap;
import java.util.Map;

public class RequestedProof {

    public Map<String, RevealedAttributeInfo> revealed_attrs = new HashMap<>();
    public Map<String, RevealedAttributeGroupInfo> revealed_attr_groups  = new HashMap<>();
    public Map<String, String> self_attested_attrs = new HashMap<>();
    public Map<String, SubProofReferent> unrevealed_attrs = new HashMap<>();
    public Map<String, SubProofReferent> predicates = new HashMap<>();

    public RequestedProof(){}

    @JsonCreator
    public RequestedProof(
            @JsonProperty("revealed_attrs") Map<String, RevealedAttributeInfo> revealed_attrs,
            @JsonProperty("revealed_attr_groups") Map<String, RevealedAttributeGroupInfo> revealed_attr_groups,
            @JsonProperty("self_attested_attrs") Map<String, String> self_attested_attrs,
            @JsonProperty("unrevealed_attrs") Map<String, SubProofReferent> unrevealed_attrs,
            @JsonProperty("predicates") Map<String, SubProofReferent> predicates)
    {
        this.revealed_attrs = revealed_attrs;
        this.revealed_attr_groups = revealed_attr_groups;
        this.self_attested_attrs = self_attested_attrs;
        this.unrevealed_attrs = unrevealed_attrs;
        this.predicates = predicates;
    }
}
