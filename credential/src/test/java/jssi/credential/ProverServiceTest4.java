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

package jssi.credential;

import org.junit.jupiter.api.Test;
import jssi.credential.credential.AttributeValue;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ProverServiceTest4 {

    private AttributeValue attr_values() {
        return new AttributeValue("Alex", "123");
    }

    private Map<String, AttributeValue> cred_values() {
        Map<String, AttributeValue> result = new HashMap<>();
        result.put("name", attr_values());
        return result;
    }

    @Test
    void getCredentialValuesForAttribute() {
        ProverService ps = new ProverService();
        AttributeValue result = ps.getCredentialValuesForAttribute(cred_values(), "name");
        assertEquals(result, attr_values());

        result = ps.getCredentialValuesForAttribute(cred_values(), "Name");
        assertEquals(result, attr_values());

        result = ps.getCredentialValuesForAttribute(cred_values(), "  na me ");
        assertEquals(result, attr_values());

     }
}