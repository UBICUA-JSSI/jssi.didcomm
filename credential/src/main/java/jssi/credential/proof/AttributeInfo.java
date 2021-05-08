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

import java.util.List;

public class AttributeInfo {

    public String name;
    public List<String> names;
    public Query restrictions;
    public NonRevokedInterval non_revoked;

    public AttributeInfo(
            String name,
            List<String> names,
            Query restrictions,
            NonRevokedInterval non_revoked)
    {
        this.name = name;
        this.names = names;
        this.restrictions = restrictions;
        this.non_revoked = non_revoked;
    }
}
