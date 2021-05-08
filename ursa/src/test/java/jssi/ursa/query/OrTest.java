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

class OrTest {

    @Test
    void Empty() throws JsonProcessingException {
        String query = "{\"$or\":[]}";
        String result = Query.build(query).toString();
        assertEquals(query, result);
    }

    @Test
    void Eq() throws JsonProcessingException {
        String query = String.format("{\"$or\":[{\"%s\":\"%s\"}]}", "name", "value");
        String result = Query.build(query).toString();
        assertEquals(query, result);
    }

    @Test
    void Neq() throws JsonProcessingException {
        String query = String.format("{\"$or\":[{\"%s\":{\"$neq\":\"%s\"}}]}", "name", "value");
        Query result =  Query.build(query);
        assertEquals(query, result.toString());
    }

    @Test
    void Gt() throws JsonProcessingException {
        String query = String.format("{\"$or\":[{\"%s\":{\"$gt\":\"%s\"}}]}", "name", "value");
        String result = Query.build(query).toString();
        assertEquals(query, result);
    }

    @Test
    void Gte() throws JsonProcessingException {
        String query = String.format("{\"$or\":[{\"%s\":{\"$gte\":\"%s\"}}]}", "name", "value");
        String result = Query.build(query).toString();
        assertEquals(query, result);
    }

    @Test
    void Lt() throws JsonProcessingException {
        String query = String.format("{\"$or\":[{\"%s\":{\"$lt\":\"%s\"}}]}", "name", "value");
        String result = Query.build(query).toString();
        assertEquals(query, result);
    }

    @Test
    void Lte() throws JsonProcessingException {
        String query = String.format("{\"$or\":[{\"%s\":{\"$lte\":\"%s\"}}]}", "name", "value");
        String result = Query.build(query).toString();
        assertEquals(query, result);
    }

    @Test
    void Like() throws JsonProcessingException {
        String query = String.format("{\"$or\":[{\"%s\":{\"$like\":\"%s\"}}]}", "name", "value");
        String result = Query.build(query).toString();
        assertEquals(query, result);
    }

    @Test
    void SingleIn() throws JsonProcessingException {
        String query = String.format("{\"$or\":[{\"%s\":{\"$in\":[\"%s\"]}}]}", "name", "value");
        String result = Query.build(query).toString();
        assertEquals(query, result);
    }

    @Test
    void ListNot() throws JsonProcessingException {
        String query = String.format("{\"$or\":[{\"$not\":{\"%s\":\"%s\"}},{\"$not\":{\"%s\":\"%s\"}},{\"$not\":{\"%s\":\"%s\"}}]}", "name1", "value1", "name2", "value2", "name3", "value3");
        Query result =  Query.build(query);
        assertEquals(query, result.toString());
    }

    @Test
    void SingleNot() throws JsonProcessingException {
        String query = String.format("{\"$or\":[{\"$not\":{\"%s\":\"%s\"}}]}", "name1", "value1");
        Query result =  Query.build(query);
        assertEquals(query, result.toString());
    }

    @Test
    void ListEq() throws JsonProcessingException {
        String query = String.format("{\"$or\":[{\"%s\":\"%s\"},{\"%s\":\"%s\"},{\"%s\":\"%s\"}]}", "name1", "value1", "name2", "value2", "name3", "value3");
        String result = Query.build(query).toString();
        assertEquals(query, result);
    }

    @Test
    void ListNeq() throws JsonProcessingException {
        String query = String.format("{\"$or\":[{\"%s\":{\"$neq\":\"%s\"}},{\"%s\":{\"$neq\":\"%s\"}},{\"%s\":{\"$neq\":\"%s\"}}]}", "name1", "value1", "name2", "value2", "name3", "value3");
        String result = Query.build(query).toString();
        assertEquals(query, result);
    }

    @Test
    void ListGt() throws JsonProcessingException {
        String query = String.format("{\"$or\":[{\"%s\":{\"$gt\":\"%s\"}},{\"%s\":{\"$gt\":\"%s\"}},{\"%s\":{\"$gt\":\"%s\"}}]}", "name1", "value1", "name2", "value2", "name3", "value3");
        String result = Query.build(query).toString();
        assertEquals(query, result);
    }

    @Test
    void ListGte() throws JsonProcessingException {
        String query = String.format("{\"$or\":[{\"%s\":{\"$gte\":\"%s\"}},{\"%s\":{\"$gte\":\"%s\"}},{\"%s\":{\"$gte\":\"%s\"}}]}", "name1", "value1", "name2", "value2", "name3", "value3");
        String result = Query.build(query).toString();
        assertEquals(query, result);
    }

    @Test
    void ListLt() throws JsonProcessingException {
        String query = String.format("{\"$or\":[{\"%s\":{\"$lt\":\"%s\"}},{\"%s\":{\"$lt\":\"%s\"}},{\"%s\":{\"$lt\":\"%s\"}}]}", "name1", "value1", "name2", "value2", "name3", "value3");
        String result = Query.build(query).toString();
        assertEquals(query, result);
    }

    @Test
    void ListLte() throws JsonProcessingException {
        String query = String.format("{\"$or\":[{\"%s\":{\"$lte\":\"%s\"}},{\"%s\":{\"$lte\":\"%s\"}},{\"%s\":{\"$lte\":\"%s\"}}]}", "name1", "value1", "name2", "value2", "name3", "value3");
        String result = Query.build(query).toString();
        assertEquals(query, result);
    }

    @Test
    void ListLike() throws JsonProcessingException {
        String query = String.format("{\"$or\":[{\"%s\":{\"$like\":\"%s\"}},{\"%s\":{\"$like\":\"%s\"}},{\"%s\":{\"$like\":\"%s\"}}]}", "name1", "value1", "name2", "value2", "name3", "value3");
        String result = Query.build(query).toString();
        assertEquals(query, result);
    }

    @Test
    void ListIn() throws JsonProcessingException {
        String query = String.format("{\"$or\":[{\"%s\":{\"$in\":[\"%s\"]}},{\"%s\":{\"$in\":[\"%s\"]}},{\"%s\":{\"$in\":[\"%s\"]}}]}", "name1", "value1", "name2", "value2", "name3", "value3");
        Query result =  Query.build(query);
        assertEquals(query, result.toString());
    }

    @Test
    void Mixed() throws JsonProcessingException {
        String query = String.format("{\"$or\":[{\"%s\":\"%s\"},{\"%s\":{\"$neq\":\"%s\"}},{\"%s\":{\"$gt\":\"%s\"}},{\"%s\":{\"$gte\":\"%s\"}},{\"%s\":{\"$lt\":\"%s\"}},{\"%s\":{\"$lte\":\"%s\"}},{\"%s\":{\"$like\":\"%s\"}},{\"%s\":{\"$in\":[\"%s\",\"%s\"]}},{\"$not\":{\"%s\":\"%s\"}}]}",
                "name1", "value1",
                "name2", "value2",
                "name3", "value3",
                "name4", "value4",
                "name5", "value5",
                "name6", "value6",
                "name7", "value7",
                "name8", "value8a", "value8b",
                "name9", "value9");
        Query result = Query.build(query);
        assertEquals(query, result.toString());
    }


}