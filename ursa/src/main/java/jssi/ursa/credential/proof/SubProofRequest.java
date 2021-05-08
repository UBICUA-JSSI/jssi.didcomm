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

import java.util.ArrayList;
import java.util.List;

public class SubProofRequest {

    public List<String> revealed_attrs;
    public List<Predicate>  predicates;

    private SubProofRequest(List<String> revealed_attr, List<Predicate>  predicates){
        this.revealed_attrs = revealed_attr;
        this.predicates = predicates;
    }

    public static SubProofRequestBuilder builder(){
        return new SubProofRequestBuilder();
    }

    public static class SubProofRequestBuilder{

        private List<String> revealed_attrs = new ArrayList<>();
        private List<Predicate>  predicates = new ArrayList<>();

        public void addRevealedAttr(String attr) {
            revealed_attrs.add(attr);
        }

        public void addPredicate(String attr_name, String p_type, int value) {

            PredicateType predicateType;
            switch (p_type){
                case "GE":
                    predicateType = PredicateType.GE;
                    break;
                case "LE":
                    predicateType = PredicateType.LE;
                    break;
                case "GT":
                    predicateType = PredicateType.GT;
                    break;
                case "LT":
                    predicateType = PredicateType.LT;
                    break;
                default:
                    predicateType = PredicateType.UNKNOWN;
            }

            Predicate predicate = new Predicate(attr_name, predicateType, value);
            predicates.add(predicate);
        }

        public SubProofRequest build(){
            return new SubProofRequest(revealed_attrs, predicates);
        }
    }
}
