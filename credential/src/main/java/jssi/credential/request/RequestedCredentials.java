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

import jssi.credential.util.Validatable;
import jssi.credential.util.ValidateException;

import java.util.Map;

public class RequestedCredentials implements Validatable {

    public Map<String, String> self_attested_attributes;
    public Map<String, RequestedAttribute> requested_attributes;
    public Map<String, ProvingCredentialKey> requested_predicates;

    public RequestedCredentials(
            Map<String, String> self_attested_attributes,
            Map<String, RequestedAttribute> requested_attributes,
            Map<String, ProvingCredentialKey> requested_predicates)
    {
        this.self_attested_attributes = self_attested_attributes;
        this.requested_attributes = requested_attributes;
        this.requested_predicates = requested_predicates;
    }

    @Override
    public void validate() throws ValidateException {
        if (self_attested_attributes.isEmpty() && requested_attributes.isEmpty() && requested_predicates.isEmpty()) {
            throw  new ValidateException("Requested Credentials validation failed: `self_attested_attributes` and `requested_attributes` and `requested_predicates` are empty");
        }
    }
}
