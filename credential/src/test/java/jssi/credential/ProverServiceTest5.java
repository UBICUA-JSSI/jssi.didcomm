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
import jssi.credential.credential.Credential;
import jssi.ursa.credential.query.Query;
import jssi.ursa.credential.query.QueryOp;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ProverServiceTest5 {

    private static final String QUALIFIABLE_TAG = "issuer_did";
    private static final String NOT_QUALIFIABLE_TAG = "name";
    private static final String VALUE = "1";

    @Test
    void doubleRestrictions() {
        ProverService ps = new ProverService();

        Query query = new Query(QueryOp.Eq, QUALIFIABLE_TAG, VALUE);
        query = ps.doubleRestrictions(query);

        List<Query> operators = new ArrayList<>();
        operators.add(new Query(QueryOp.Eq, QUALIFIABLE_TAG, VALUE));
        operators.add(new Query(QueryOp.Eq, Credential.addExtraTagSuffix(QUALIFIABLE_TAG), VALUE));
        Query expected = new Query(QueryOp.Or, operators);
        assertEquals(query.toString(), expected.toString());

        query = new Query(QueryOp.Eq, NOT_QUALIFIABLE_TAG, VALUE);
        query = ps.doubleRestrictions(query);
        expected = new Query(QueryOp.Eq, NOT_QUALIFIABLE_TAG, VALUE);
        assertEquals(query.toString(), expected.toString());

        operators = new ArrayList<>();
        operators.add(new Query(QueryOp.Eq, QUALIFIABLE_TAG, VALUE));
        operators.add(new Query(QueryOp.Eq, NOT_QUALIFIABLE_TAG, VALUE));
        query = new Query(QueryOp.And, operators);
        query = ps.doubleRestrictions(query);

        List<Query> or = new ArrayList<>();
        or.add(new Query(QueryOp.Eq, QUALIFIABLE_TAG, VALUE));
        or.add(new Query(QueryOp.Eq, Credential.addExtraTagSuffix(QUALIFIABLE_TAG), VALUE));
        expected = new Query(QueryOp.Or, or);
        List<Query> and = new ArrayList<>();
        and.add(expected);
        and.add(new Query(QueryOp.Eq, NOT_QUALIFIABLE_TAG, VALUE));
        expected = new Query(QueryOp.And, and);
        assertEquals(query.toString(), expected.toString());
     }
}