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

import java.math.BigInteger;

public class Predicate {

    String attr_name;
    PredicateType p_type;
    int value;

    @JsonCreator
    public Predicate(
            @JsonProperty("attr_name") String attr_name,
            @JsonProperty("p_type") PredicateType p_type,
            @JsonProperty("value") int value){
        this.attr_name = attr_name;
        this.p_type = p_type;
        this.value = value;
    }

    public int getDelta(int attr_value) {

        switch (p_type){
            case GE:
                return attr_value - this.value;
            case GT:
                return attr_value - this.value - 1;
            case LE:
                return this.value - attr_value;
            case LT:
                return this.value - attr_value - 1;
        }

        return 0;
    }

    public BigInteger getDeltaPrime(){
        switch (p_type){
            case GE:
            case LE:
                return BigInteger.valueOf(this.value);
            case GT:
                return BigInteger.valueOf(this.value + 1);
            case LT:
                return BigInteger.valueOf(this.value - 1);
        }

        return BigInteger.ZERO;
    }

    public boolean isLess(){
        switch (p_type){
            case GE:
            case GT:
                return false;
            default:
                return true;
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Predicate predicate = (Predicate) o;

        if (value != predicate.value) return false;
        if (!attr_name.equals(predicate.attr_name)) return false;
        return p_type == predicate.p_type;
    }
}
