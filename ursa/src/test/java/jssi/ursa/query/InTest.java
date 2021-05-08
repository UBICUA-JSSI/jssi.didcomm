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

package jssi.ursa.query;

import com.fasterxml.jackson.core.JsonProcessingException;
import jssi.ursa.credential.query.Query;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class InTest {

    @Test
    void InSingle() throws JsonProcessingException {
        String query = String.format("{\"%s\":{\"$in\":[\"%s\"]}}", "name", "value1");
        String result = Query.build(query).toString();
        assertEquals(query, result);
    }


    @Test
    void InList() throws JsonProcessingException {
        String query = String.format("{\"%s\":{\"$in\":[\"%s\",\"%s\",\"%s\"]}}", "name", "value1", "value2", "value3");
        String result = Query.build(query).toString();
        assertEquals(query, result);
    }
}