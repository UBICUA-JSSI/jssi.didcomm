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
import jssi.credential.proof.ProofRequestsVersion;
import jssi.ursa.credential.query.Query;
import jssi.ursa.credential.query.QueryOp;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static jssi.credential.ProverService.ATTRIBUTE_EXISTENCE_MARKER;
import static org.junit.jupiter.api.Assertions.assertEquals;

class ProverServiceTest6 {


    private static final String ATTR_NAME = "name";
    private static final String ATTR_NAME_2 = "name_2";
    private static final String ATTR_REFERENT = "attr_1";
    private static String SCHEMA_ID = "NcYxiDXkpYi6ov5FcYDi1e:2:gvt:1.0";
    private static String CRED_DEF_ID = "NcYxiDXkpYi6ov5FcYDi1e:3:CL:NcYxiDXkpYi6ov5FcYDi1e:2:gvt:1.0:tag";

    @Test
    void name() {
        ProverService ps = new ProverService();

        Query query = ps.extendProofRequestRestrictions(
                ProofRequestsVersion.V2,
                ATTR_NAME,
                null,
                ATTR_REFERENT,
                null,
                null);

        List<Query> operators = new ArrayList<>();
        operators.add(new Query(QueryOp.Eq, "attr::name::marker", ATTRIBUTE_EXISTENCE_MARKER));
        Query expected = new Query(QueryOp.And, operators);
        assertEquals(query.toString(), expected.toString());
    }

    @Test
    void names() {
        ProverService ps = new ProverService();
        List<String> names = new ArrayList<>();
        names.add(ATTR_NAME);
        names.add(ATTR_NAME_2);
        Query query = ps.extendProofRequestRestrictions(
                ProofRequestsVersion.V2,
                null,
                names,
                ATTR_REFERENT,
                null,
                null);

        List<Query> operators = new ArrayList<>();
        operators.add(new Query(QueryOp.Eq, "attr::name::marker", ATTRIBUTE_EXISTENCE_MARKER));
        operators.add(new Query(QueryOp.Eq, "attr::name_2::marker", ATTRIBUTE_EXISTENCE_MARKER));
        Query expected = new Query(QueryOp.And, operators);
        assertEquals(query.toString(), expected.toString());
    }

    @Test
    void restrictions() {
        ProverService ps = new ProverService();

        List<Query> and = new ArrayList<>();
        and.add(new Query(QueryOp.Eq, "schema_id", SCHEMA_ID));
        and.add(new Query(QueryOp.Eq, "cred_def_id", CRED_DEF_ID));
        Query restrictions = new Query(QueryOp.And, and);
        Query query = ps.extendProofRequestRestrictions(
                ProofRequestsVersion.V2,
                ATTR_NAME,
                null,
                ATTR_REFERENT,
                restrictions,
                null);

        and = new ArrayList<>();
        and.add(new Query(QueryOp.Eq, "schema_id", SCHEMA_ID));
        and.add(new Query(QueryOp.Eq, "cred_def_id", CRED_DEF_ID));
        Query expAnd = new Query(QueryOp.And, and);

        List<Query> exp = new ArrayList<>();
        exp.add(new Query(QueryOp.Eq, "attr::name::marker", ATTRIBUTE_EXISTENCE_MARKER));
        exp.add(expAnd);
        Query expected = new Query(QueryOp.And, exp);
        assertEquals(query.toString(), expected.toString());
    }

    @Test
    void extra() {
        ProverService ps = new ProverService();

        Map<String, Query> extra = new HashMap<>();
        extra.put(ATTR_REFERENT, new Query(QueryOp.Eq, "name", "Alex"));

        Query query = ps.extendProofRequestRestrictions(
                ProofRequestsVersion.V2,
                ATTR_NAME,
                null,
                ATTR_REFERENT,
                null,
                extra);
        List<Query> operators = new ArrayList<>();
        operators.add(new Query(QueryOp.Eq, "attr::name::marker", ATTRIBUTE_EXISTENCE_MARKER));
        operators.add(new Query(QueryOp.Eq, "name", "Alex"));
        Query expected = new Query(QueryOp.And, operators);
        assertEquals(query.toString(), expected.toString());
    }

    @Test
    void restrictionsAndExra() {
        ProverService ps = new ProverService();

        List<Query> and = new ArrayList<>();
        and.add(new Query(QueryOp.Eq, "schema_id", SCHEMA_ID));
        and.add(new Query(QueryOp.Eq, "cred_def_id", CRED_DEF_ID));
        Query restrictions = new Query(QueryOp.And, and);

        Map<String, Query> extra = new HashMap<>();
        extra.put(ATTR_REFERENT, new Query(QueryOp.Eq, "name", "Alex"));

        Query query = ps.extendProofRequestRestrictions(
                ProofRequestsVersion.V2,
                ATTR_NAME,
                null,
                ATTR_REFERENT,
                restrictions,
                extra);

        and = new ArrayList<>();
        and.add(new Query(QueryOp.Eq, "schema_id", SCHEMA_ID));
        and.add(new Query(QueryOp.Eq, "cred_def_id", CRED_DEF_ID));
        Query expAnd = new Query(QueryOp.And, and);

        List<Query> exp = new ArrayList<>();
        exp.add(new Query(QueryOp.Eq, "attr::name::marker", ATTRIBUTE_EXISTENCE_MARKER));
        exp.add(expAnd);
        exp.add(new Query(QueryOp.Eq, "name", "Alex"));
        Query expected = new Query(QueryOp.And, exp);
        assertEquals(query.toString(), expected.toString());
    }

    @Test
    void restrictionsOrExra() {
        ProverService ps = new ProverService();

        List<Query> or = new ArrayList<>();
        or.add(new Query(QueryOp.Eq, "schema_id", SCHEMA_ID));
        or.add(new Query(QueryOp.Eq, "schema_id", "schema_id_2"));
        Query restrictions = new Query(QueryOp.Or, or);

        Map<String, Query> extra = new HashMap<>();
        or = new ArrayList<>();
        or.add( new Query(QueryOp.Eq, "name", "Alex"));
        or.add( new Query(QueryOp.Eq, "name", "Alexander"));
        extra.put(ATTR_REFERENT, new Query(QueryOp.Or, or));

        Query query = ps.extendProofRequestRestrictions(
                ProofRequestsVersion.V2,
                ATTR_NAME,
                null,
                ATTR_REFERENT,
                restrictions,
                extra);

        or = new ArrayList<>();
        or.add(new Query(QueryOp.Eq, "schema_id", SCHEMA_ID));
        or.add(new Query(QueryOp.Eq, "schema_id", "schema_id_2"));
        Query resOr = new Query(QueryOp.Or, or);

        or = new ArrayList<>();
        or.add(new Query(QueryOp.Eq, "name", "Alex"));
        or.add(new Query(QueryOp.Eq, "name", "Alexander"));
        Query extraOr = new Query(QueryOp.Or, or);

        List<Query> exp = new ArrayList<>();
        exp.add(new Query(QueryOp.Eq, "attr::name::marker", ATTRIBUTE_EXISTENCE_MARKER));
        exp.add(resOr);
        exp.add(extraOr);
        Query expected = new Query(QueryOp.And, exp);
        assertEquals(query.toString(), expected.toString());
    }
}