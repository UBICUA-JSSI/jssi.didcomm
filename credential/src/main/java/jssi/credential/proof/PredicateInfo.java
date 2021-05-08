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

import jssi.ursa.credential.query.Query;

public class PredicateInfo {

    public String name;
    public PredicateTypes p_type;
    public int p_value;
    public Query restrictions;
    public NonRevokedInterval non_revoked;

    public PredicateInfo(
            String name,
            PredicateTypes p_type,
            int p_value,
            Query restrictions,
            NonRevokedInterval non_revoked)
    {
        this.name = name;
        this.p_type = p_type;
        this.p_value = p_value;
        this.restrictions = restrictions;
        this.non_revoked = non_revoked;
    }
}
