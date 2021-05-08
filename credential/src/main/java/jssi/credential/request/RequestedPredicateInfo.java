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

package jssi.credential.request;

import jssi.credential.proof.PredicateInfo;

public class RequestedPredicateInfo {
    public String predicate_referent;
    public PredicateInfo predicate_info;

    public RequestedPredicateInfo(String predicate_referent, PredicateInfo predicate_info){
        this.predicate_referent = predicate_referent;
        this.predicate_info = predicate_info;
    }
}
