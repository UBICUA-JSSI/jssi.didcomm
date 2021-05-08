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

import java.util.ArrayList;
import java.util.List;

public class CredentialSchema {

    public List<String> attrs;

    private CredentialSchema(List<String> attrs){
        this.attrs = attrs;
    }

    public static CredentialSchemaBuilder builder(){
        return new CredentialSchemaBuilder();
    }

    /**
     * Creates and returns credential schema entity builder.
     *
     * Example
     *
     * CredentialSchemaBuilder builder = CredentialSchema.builder();
     * builder.addAttr("sex");
     * builder.addAttr("name");
     * CredentialSchema credentialSchema = builder.build();
     */
    public static class CredentialSchemaBuilder{
        List<String> attrs = new ArrayList<>();

        public CredentialSchemaBuilder addAttr(String attr){
            attrs.add(attr);
            return this;
        }

        public CredentialSchema build(){
            return new CredentialSchema(attrs);
        }
    }
}
