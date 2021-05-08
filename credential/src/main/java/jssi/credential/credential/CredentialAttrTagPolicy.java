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

package jssi.credential.credential;

import java.util.Set;
import java.util.stream.Collectors;

public class CredentialAttrTagPolicy {

    public Set<String> taggable;

    public CredentialAttrTagPolicy(Set<String> taggable){
        this.taggable = taggable.stream()
                .map(item -> item.replace(" ", "").toLowerCase()).collect(Collectors.toSet());
    }

    public boolean isTaggable(String attr_name) {
       return taggable.contains(attr_name.replace(" ", "").toLowerCase());
    }
}
