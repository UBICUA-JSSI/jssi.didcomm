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

package jssi.ursa.registry;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import jssi.ursa.pair.Pair;
import jssi.ursa.pair.PairDeserializer;
import jssi.ursa.pair.PairSerializer;

public class RevocationPublicKey {

    @JsonDeserialize(using = PairDeserializer.class)
    @JsonSerialize(using = PairSerializer.class)
    public Pair z;

    @JsonCreator
    public RevocationPublicKey(@JsonProperty("z") Pair z){
        this.z = z;
    }
}
