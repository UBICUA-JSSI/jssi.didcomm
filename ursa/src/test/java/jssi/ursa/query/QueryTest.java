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

class QueryTest {

    @Test
    void Eq() throws JsonProcessingException {
        String query = String.format("{\"%s\":\"%s\"}", "name", "value");
        String result = Query.build(query).toString();
        assertEquals(query, result);
    }

    @Test
    void Neq() throws JsonProcessingException {
        String query = String.format("{\"%s\":{\"$neq\":\"%s\"}}", "name", "value");
        String result = Query.build(query).toString();
        assertEquals(query, result);
    }

    @Test
    void Gt() throws JsonProcessingException {
        String query = String.format("{\"%s\":{\"$gt\":\"%s\"}}", "name", "value");
        String result = Query.build(query).toString();
        assertEquals(query, result);
    }

    @Test
    void Gte() throws JsonProcessingException {
        String query = String.format("{\"%s\":{\"$gte\":\"%s\"}}", "name", "value");
        String result = Query.build(query).toString();
        assertEquals(query, result);
    }

    @Test
    void Lt() throws JsonProcessingException {
        String query = String.format("{\"%s\":{\"$lt\":\"%s\"}}", "name", "value");
        String result = Query.build(query).toString();
        assertEquals(query, result);
    }

    @Test
    void Lte() throws JsonProcessingException {
        String query = String.format("{\"%s\":{\"$lte\":\"%s\"}}", "name", "value");
        String result = Query.build(query).toString();
        assertEquals(query, result);
    }

    @Test
    void Like() throws JsonProcessingException {
        String query = String.format("{\"%s\":{\"$like\":\"%s\"}}", "name", "value");
        String result = Query.build(query).toString();
        assertEquals(query, result);
    }

    @Test
    void Empty() throws JsonProcessingException {
        String query = "{}";
        String result = Query.build(query).toString();
        assertEquals("{\"$and\":[]}", result);
    }
}